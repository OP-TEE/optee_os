// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Missing Link Electronics, Inc.
 */

#include <drivers/versal_mbox.h>
#include <drivers/versal_pmc.h>
#include <drivers/versal_ocp.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

/* Protocol API with Versal PLM Firmware on PMC */
#define OCP_MODULE_SHIFT 8
#define OCP_MODULE 13
#define OCP_API_ID(_id) (SHIFT_U32(OCP_MODULE, OCP_MODULE_SHIFT) | (_id))

/*
 * The following symbols/types/definitions are taken from AMD/Xilinx
 * embeddedsw::lib/sw_services/xilocp/src/common/xocp_def.h
 * v2024.2
 */

enum versal_ocp_api_id {
	API_FEATURES			= 0,
	EXTEND_HWPCR			= 1,
	GET_HWPCR			= 2,
	GET_HWPCRLOG			= 3,
	GENDMERESP			= 4,
	DEVAKINPUT			= 5,
	GETCERTUSERCFG			= 6,
	GETX509CERT			= 7,
	ATTESTWITHDEVAK			= 8,
	SET_SWPCRCONFIG			= 9,
	EXTEND_SWPCR			= 10,
	GET_SWPCR			= 11,
	GET_SWPCRLOG			= 12,
	GET_SWPCRDATA			= 13,
	GEN_SHARED_SECRET		= 14,
	ATTEST_WITH_KEYWRAP_DEVAK	= 15,
	API_MAX				= 16
};

#define VERSAL_OCP_EXTENDED_HASH_SIZE_IN_BYTES 48

/*
 * The following symbols/types/definitions are taken from AMD/Xilinx
 * embeddedsw::lib/sw_services/xilocp/src/common/xocp_common.h
 * v2024.2
 */

struct versal_ocp_swpcr_extend_params {
	uint32_t pcr_num;
	uint32_t measurement_idx;
	uint32_t data_size;
	uint32_t overwrite;
	uint64_t data_addr;
};

struct versal_ocp_swpcr_log_read_data {
	uint32_t pcr_num;
	uint32_t log_size;
	uint64_t pcr_log_addr;
	uint32_t digest_count;
};

struct versal_ocp_swpcr_read_data {
	uint32_t pcr_num;
	uint32_t measurement_idx;
	uint32_t data_start_idx;
	uint32_t buf_size;
	uint64_t buf_addr;
	uint32_t returned_bytes;
};

struct versal_ocp_x509_cert {
	uint64_t cert_addr;
	uint64_t actual_len_addr;
	uint32_t cert_size;
	enum versal_ocp_dev_key	dev_key_sel;
	uint32_t is_csr;
};

struct versal_ocp_attest {
	uint64_t hash_addr;
	uint64_t signature_addr;
	uint32_t reserved;
	uint32_t hash_len;
};

/*
 * The following helper functions shall be regarded as a possible general API
 * towards constructing "struct versal_ipi_cmd" instances. After extracting them
 * into a separate drivers/ file, like drivers/versal_ipi_cmd.c, they may be
 * used by other existing drivers in the future, too. For now, they shall live
 * here, since versal_ocp.c is the only user [1].
 *
 * [1] https://github.com/OP-TEE/optee_os/pull/7726#issuecomment-4237954478
 */

static TEE_Result versal_ipi_cmd_ibuf_alloc(struct versal_ipi_cmd *cmd,
					    void *buf, size_t len, size_t *idx)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_mbox_mem mem = {};

	if (cmd->ibuf_count >= VERSAL_MAX_IPI_BUF)
		panic();

	ret = versal_mbox_alloc(len, buf, &mem);
	if (ret)
		return ret;

	cmd->ibuf[cmd->ibuf_count].mem = mem;
	if (idx)
		*idx = cmd->ibuf_count;
	cmd->ibuf_count++;
	return ret;
}

static void versal_ipi_cmd_free(struct versal_ipi_cmd *cmd)
{
	memset(cmd->data, 0, sizeof(cmd->data));
	cmd->data_count = 0;

	for (size_t idx = 0; idx < cmd->ibuf_count; idx++)
		versal_mbox_free(&cmd->ibuf[idx].mem);
	cmd->ibuf_count = 0;
}

static void versal_ipi_cmd_data_push_val(struct versal_ipi_cmd *cmd,
					 uint32_t val)
{
	if (cmd->data_count >= VERSAL_MAX_IPI_DATA)
		panic();

	cmd->data[cmd->data_count++] = val;
}

static void versal_ipi_cmd_data_push_ptr(struct versal_ipi_cmd *cmd, void *ptr)
{
	uint32_t low = 0;
	uint32_t hi = 0;

	if (cmd->data_count >= (VERSAL_MAX_IPI_DATA - 1))
		panic();

	reg_pair_from_64(virt_to_phys(ptr), &hi, &low);
	cmd->data[cmd->data_count++] = low;
	cmd->data[cmd->data_count++] = hi;
}

static TEE_Result versal_ipi_cmd_data_push_ibuf(struct versal_ipi_cmd *cmd,
						void *buf, size_t len,
						size_t *idx)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t target_idx = 0;

	if (cmd->ibuf_count >= VERSAL_MAX_IPI_BUF)
		panic();
	if (cmd->data_count >= (VERSAL_MAX_IPI_DATA - 1))
		panic();

	ret = versal_ipi_cmd_ibuf_alloc(cmd, buf, len, &target_idx);
	if (ret)
		return ret;

	if (idx)
		*idx = target_idx;

	versal_ipi_cmd_data_push_ptr(cmd, cmd->ibuf[target_idx].mem.buf);
	return ret;
}

static void *versal_ipi_cmd_ibuf_get(struct versal_ipi_cmd *cmd, size_t idx)
{
	if (idx >= cmd->ibuf_count)
		panic();

	return cmd->ibuf[idx].mem.buf;
}

static paddr_t versal_ipi_cmd_ibuf_get_paddr(struct versal_ipi_cmd *cmd,
					     size_t idx)
{
	if (idx >= cmd->ibuf_count)
		panic();

	return virt_to_phys(cmd->ibuf[idx].mem.buf);
}

static void versal_ipi_cmd_ibuf_fetch(struct versal_ipi_cmd *cmd,
				      void *dst, size_t len, size_t idx)
{
	if (idx >= cmd->ibuf_count)
		panic();
	if (len > cmd->ibuf[idx].mem.len)
		panic();

	memcpy(dst, cmd->ibuf[idx].mem.buf, len);
}

/*
 * The following functions shall mimic the XilOCP client side interface from
 * AMD/Xilinx embeddedsw::lib/sw_services/xilocp/src/client/xocp_client.h
 * v2024.2
 */

/* capture PLM status/error code */
static uint32_t plm_status;
struct mutex plm_status_lock = MUTEX_INITIALIZER;

uint32_t versal_ocp_plm_status_get(void)
{
	uint32_t status = 0;

	mutex_lock(&plm_status_lock);
	status = plm_status;
	mutex_unlock(&plm_status_lock);

	return status;
}

uint32_t versal_ocp_status_get(void)
{
	return versal_ocp_plm_status_get() & VERSAL_OCP_STATUS_MASK;
}

TEE_Result versal_ocp_extend_hwpcr(enum versal_ocp_hwpcr pcr_num,
				   void *data, uint32_t data_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};

	if (!data || !data_size)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(EXTEND_HWPCR));

	versal_ipi_cmd_data_push_val(&cmd, pcr_num);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, data, data_size, NULL);
	if (ret)
		goto out;

	versal_ipi_cmd_data_push_val(&cmd, data_size);

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID EXTEND_HWPCR failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
	}
	mutex_unlock(&plm_status_lock);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_get_hwpcr(uint32_t pcr_mask,
				void *pcr, uint32_t pcr_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx = 0;

	if (!pcr || !pcr_size)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GET_HWPCR));

	versal_ipi_cmd_data_push_val(&cmd, pcr_mask);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, pcr_size, &idx);
	if (ret)
		goto out;

	versal_ipi_cmd_data_push_val(&cmd, pcr_size);

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GET_HWPCR failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, pcr, pcr_size, idx);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_get_hwpcr_log(struct versal_ocp_hwpcr_event *events,
				    uint32_t events_size,
				    struct versal_ocp_hwpcr_log_info *loginfo)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx_events = 0;
	size_t idx_loginfo = 0;

	if (!events || !events_size || (events_size % sizeof(*events)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!loginfo)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GET_HWPCRLOG));

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, events_size,
					    &idx_events);
	if (ret)
		goto out;
	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, sizeof(*loginfo),
					    &idx_loginfo);
	if (ret)
		goto out;

	versal_ipi_cmd_data_push_val(&cmd, events_size / sizeof(*events));

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GET_HWPCRLOG failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, loginfo, sizeof(*loginfo), idx_loginfo);

	versal_ipi_cmd_ibuf_fetch(&cmd, events, events_size, idx_events);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_extend_swpcr(uint32_t pcr_num,
				   void *data, uint32_t data_size,
				   uint32_t measurement_idx, bool overwrite)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	struct versal_ocp_swpcr_extend_params params = {
		.pcr_num = pcr_num,
		.measurement_idx = measurement_idx,
		.data_size = data_size,
		.overwrite = overwrite,
		.data_addr = 0,
	};
	size_t idx = 0;

	if (!data || !data_size)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * NOTE: AMD/Xilinx XilOCP client side code does this check explicitly
	 *       before calling into PLM Firmware. Despite checking it again in
	 *       PLM Firmware. It looks like hardware can handle data buffers
	 *       beyond 48 Bytes, only, if within the first 4GiB of
	 *       RAM. Probably some kind of DMA engine issue ...?
	 */
	if (data_size > VERSAL_OCP_EXTENDED_HASH_SIZE_IN_BYTES)
		if ((vaddr_t)data >> 32)
			return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(EXTEND_SWPCR));

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, data, data_size, &idx);
	if (ret)
		goto out;

	params.data_addr = (uint64_t)versal_ipi_cmd_ibuf_get_paddr(&cmd, idx);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, &params, sizeof(params),
					    NULL);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID EXTEND_SWPCR failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
	}
	mutex_unlock(&plm_status_lock);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_get_swpcr(uint32_t pcr_mask,
				void *pcr, uint32_t pcr_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx = 0;

	if (!pcr || !pcr_size)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GET_SWPCR));

	versal_ipi_cmd_data_push_val(&cmd, pcr_mask);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, pcr_size, &idx);
	if (ret)
		goto out;

	versal_ipi_cmd_data_push_val(&cmd, pcr_size);

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GET_SWPCR failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, pcr, pcr_size, idx);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_get_swpcr_data(uint32_t pcr_num, uint32_t measurement_idx,
				     uint32_t data_start_idx,
				     void *data, uint32_t data_size,
				     uint32_t *data_returned)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	struct versal_ocp_swpcr_read_data param = {
		.pcr_num = pcr_num,
		.measurement_idx = measurement_idx,
		.data_start_idx = data_start_idx,
		.buf_size = data_size,
		.buf_addr = 0,
		.returned_bytes = 0,
	};
	size_t idx_buf = 0;
	size_t idx_param = 0;
	struct versal_ocp_swpcr_read_data *_param = NULL;

	if (!data || !data_size || !data_returned)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GET_SWPCRDATA));

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, NULL, data_size, &idx_buf);
	if (ret)
		goto out;

	param.buf_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_buf);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, &param, sizeof(param),
					    &idx_param);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GET_SWPCRDATA failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	_param = versal_ipi_cmd_ibuf_get(&cmd, idx_param);
	*data_returned = _param->returned_bytes;

	versal_ipi_cmd_ibuf_fetch(&cmd, data, *data_returned, idx_buf);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result
versal_ocp_get_swpcr_log(uint32_t pcr_num,
			 struct versal_ocp_pcr_measurement *measurements,
			 uint32_t measurements_size,
			 uint32_t *measurements_count)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	struct versal_ocp_swpcr_log_read_data param = {
		.pcr_num = pcr_num,
		.log_size = measurements_size,
		.pcr_log_addr = 0,
		.digest_count = 0,
	};
	size_t idx_buf = 0;
	size_t idx_param = 0;
	struct versal_ocp_swpcr_log_read_data *_param = NULL;

	if (!measurements || !measurements_size ||
	    (measurements_size % sizeof(struct versal_ocp_pcr_measurement)))
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GET_SWPCRLOG));

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, NULL, measurements_size,
					&idx_buf);
	if (ret)
		goto out;

	param.pcr_log_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_buf);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, &param, sizeof(param),
					    &idx_param);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GET_SWPCRLOG failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	_param = versal_ipi_cmd_ibuf_get(&cmd, idx_param);
	*measurements_count = _param->digest_count;

	versal_ipi_cmd_ibuf_fetch(&cmd, measurements,
				  sizeof(*measurements) * *measurements_count,
				  idx_buf);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_gen_dme_resp(void *nonce, uint32_t nonce_size,
				   struct versal_ocp_dme_response *response)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx = 0;

	if (!nonce || nonce_size != VERSAL_OCP_DME_NONCE_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!response)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GENDMERESP));

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, nonce, nonce_size, NULL);
	if (ret)
		goto out;

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, sizeof(*response),
					    &idx);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GENDMERESP failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, response, sizeof(*response), idx);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_get_x509_cert(void *cert, uint32_t cert_size,
				    uint32_t *actual_cert_size,
				    enum versal_ocp_dev_key dev_key_sel,
				    bool is_csr)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	/*
	 * NOTE: PLM Firmware (function XCert_GenerateX509Cert()) actually
	 *       ignores member "cert_size" (called "MaxCertSize" there) and
	 *       has a hard-coded internal buffer of 2000 Bytes, which is used
	 *       to construct the certificate. The result is then copied to our
	 *       ibuf:
	 */
	struct versal_ocp_x509_cert param = {
		.cert_addr = 0,
		.actual_len_addr = 0,
		.cert_size = 2000,
		.dev_key_sel = dev_key_sel,
		.is_csr = is_csr ? 1 : 0,
	};
	size_t idx_cert = 0;
	size_t idx_size = 0;

	if (!cert)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GETX509CERT));

	if (cert_size > param.cert_size)
		param.cert_size = cert_size;
	ret = versal_ipi_cmd_ibuf_alloc(&cmd, NULL, param.cert_size,
					&idx_cert);
	if (ret)
		goto out;

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, NULL, sizeof(*actual_cert_size),
					&idx_size);
	if (ret)
		goto out;

	param.cert_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_cert);
	param.actual_len_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_size);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, &param, sizeof(param), NULL);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GETX509CERT failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, actual_cert_size,
				  sizeof(*actual_cert_size), idx_size);
	if (param.cert_size < *actual_cert_size) {
		EMSG("Versal PLM API ID GETX509CERT failed: wrote beyond X.509 certificate buffer, provided %u bytes, needed %u bytes",
		     param.cert_size, *actual_cert_size);
		panic();
	}
	if (cert_size < *actual_cert_size) {
		EMSG("Versal PLM API ID GETX509CERT failed: X.509 certificate buffer too small, need %u bytes",
		     *actual_cert_size);
		return TEE_ERROR_GENERIC;
	}

	versal_ipi_cmd_ibuf_fetch(&cmd, cert, *actual_cert_size, idx_cert);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_attest_with_devak(void *hash, uint32_t hash_size,
					void *signature,
					uint32_t signature_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	struct versal_ocp_attest param = {
		.hash_addr = 0,
		.signature_addr = 0,
		.reserved = 0,
		.hash_len = hash_size,
	};
	size_t idx_hash = 0;
	size_t idx_sign = 0;

	if (!hash || !hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!signature ||
	    signature_size != VERSAL_OCP_ECC_P384_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(ATTESTWITHDEVAK));

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, hash, hash_size, &idx_hash);
	if (ret)
		goto out;

	ret = versal_ipi_cmd_ibuf_alloc(&cmd, NULL, signature_size, &idx_sign);
	if (ret)
		goto out;

	param.hash_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_hash);
	param.signature_addr = versal_ipi_cmd_ibuf_get_paddr(&cmd, idx_sign);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, &param, sizeof(param), NULL);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID ATTESTWITHDEVAK failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, signature,
				  VERSAL_OCP_ECC_P384_SIZE_BYTES, idx_sign);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_attest_with_key_wrap_devak(void *attest_buf,
						 uint32_t attest_buf_size,
						 uint32_t pub_key_offset,
						 void *signature,
						 uint32_t signature_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx_buf = 0;
	size_t idx_sign = 0;
	void *_attest_buf = NULL;

	/*
	 * NOTE: The buffer with data to be attested has 2 "components":
	 *       - the actual input data to be attested
	 *       - the output RSA 3072 public key (768 Bytes, included in
	 *         attestation)
	 *
	 *       The space for the RSA public key is supposed to be located at
	 *       the end of the buffer at the offset specified by argument
	 *       "pub_key_offset".
	 *
	 *       For an unknown reason PLM Firmware
	 *       (XOcp_AttestWithKeyWrapDevAkIpi()) checks parameter
	 *       "attest_buf_size" (called "AttnPloadSize" there) for being
	 *       strictly _greater_ than:
	 *          public key offset +
	 *          half of struct versal_secure_rsapubkey() +
	 *          4 Bytes
	 *
	 *       At the same time the code does copy the complete struct
	 *       versal_secure_rsapubkey at the public key offset. Thus the size
	 *       check is wrong! And why "greater than"? Why not "greater or
	 *       equal"?
	 */
	if (!attest_buf ||
	    (attest_buf_size <
	     (pub_key_offset + sizeof(struct versal_secure_rsapubkey))))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!signature ||
	    signature_size != VERSAL_OCP_ECC_P384_SIZE_BYTES)
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd,
				     OCP_API_ID(ATTEST_WITH_KEYWRAP_DEVAK));

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, attest_buf, attest_buf_size,
					    &idx_buf);
	if (ret)
		goto out;

	versal_ipi_cmd_data_push_val(&cmd, attest_buf_size);
	versal_ipi_cmd_data_push_val(&cmd, pub_key_offset);

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, signature_size,
					    &idx_sign);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID ATTEST_WITH_KEYWRAP_DEVAK failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	_attest_buf = versal_ipi_cmd_ibuf_get(&cmd, idx_buf);
	memcpy((uint8_t *)attest_buf + pub_key_offset,
	       (uint8_t *)_attest_buf + pub_key_offset,
	       sizeof(struct versal_secure_rsapubkey));

	versal_ipi_cmd_ibuf_fetch(&cmd, signature,
				  VERSAL_OCP_ECC_P384_SIZE_BYTES, idx_sign);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}

TEE_Result versal_ocp_gen_shared_secret_with_devak(void *pub_key,
						   uint32_t pub_key_size,
						   void *shared_secret,
						   uint32_t shared_secret_size)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ipi_cmd cmd = {};
	size_t idx = 0;

	if (!pub_key ||
	    (pub_key_size != (VERSAL_OCP_ECC_P384_SIZE_BYTES * 2)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!shared_secret ||
	    (shared_secret_size != (VERSAL_OCP_ECC_P384_SIZE_BYTES * 2)))
		return TEE_ERROR_BAD_PARAMETERS;

	versal_ipi_cmd_data_push_val(&cmd, OCP_API_ID(GEN_SHARED_SECRET));

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, pub_key, pub_key_size, NULL);
	if (ret)
		goto out;

	ret = versal_ipi_cmd_data_push_ibuf(&cmd, NULL, shared_secret_size,
					    &idx);
	if (ret)
		goto out;

	mutex_lock(&plm_status_lock);
	plm_status = 0;
	if (versal_pmc_notify(&cmd, NULL, &plm_status)) {
		EMSG("Versal PLM API ID GEN_SHARED_SECRET failed: 0x%" PRIx32,
		     plm_status);
		ret = TEE_ERROR_GENERIC;
		mutex_unlock(&plm_status_lock);
		goto out;
	}
	mutex_unlock(&plm_status_lock);

	versal_ipi_cmd_ibuf_fetch(&cmd, shared_secret, shared_secret_size, idx);

out:
	versal_ipi_cmd_free(&cmd);
	return ret;
}
