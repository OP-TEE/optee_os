// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <confine_array_index.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_puf.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

/* Protocol API with the remote processor */
#define VERSAL_PUF_MODULE_SHIFT		8
#define VERSAL_PUF_MODULE		12
#define PUF_API_ID(_id) ((VERSAL_PUF_MODULE << VERSAL_PUF_MODULE_SHIFT) | (_id))

enum versal_puf_error {
	/* Registration */
	ERROR_INVALID_PARAM = 0x02,
	ERROR_INVALID_SYNDROME_MODE = 0x03,
	ERROR_SYNDROME_WORD_WAIT_TIMEOUT = 0x04,
	ERROR_PUF_DONE_WAIT_TIMEOUT = 0x07,
	ERROR_REGISTRATION_INVALID = 0x08,
	SHUTTER_GVF_MISMATCH = 0x09,
	ERROR_SYN_DATA_ERROR = 0x0A,
	IRO_FREQ_WRITE_MISMATCH = 0x0B,
	/* Regeneration */
	ERROR_CHASH_NOT_PROGRAMMED = 0x10,
	ERROR_PUF_STATUS_DONE_TIMEOUT = 0x11,
	ERROR_INVALID_REGENERATION_TYPE = 0x12,
	ERROR_INVALID_PUF_OPERATION = 0x13,
	ERROR_REGENERATION_INVALID = 0x14,
	ERROR_REGEN_PUF_HD_INVALID = 0x15,
	ERROR_INVALID_READ_HD_INPUT = 0x16,
	ERROR_PUF_DONE_KEY_NT_RDY = 0x17,
	ERROR_PUF_DONE_ID_NT_RDY = 0x18,
	ERROR_PUF_ID_ZERO_TIMEOUT = 0x19,
};

#define VERSAL_PUF_ERROR(m) { .error = (m), .name = TO_STR(m) }

static const char *versal_puf_error(uint8_t err)
{
	struct {
		enum versal_puf_error error;
		const char *name;
	} elist[] = {
		/* Registration */
		VERSAL_PUF_ERROR(ERROR_INVALID_PARAM),
		VERSAL_PUF_ERROR(ERROR_INVALID_SYNDROME_MODE),
		VERSAL_PUF_ERROR(ERROR_SYNDROME_WORD_WAIT_TIMEOUT),
		VERSAL_PUF_ERROR(ERROR_PUF_DONE_WAIT_TIMEOUT),
		VERSAL_PUF_ERROR(ERROR_REGISTRATION_INVALID),
		VERSAL_PUF_ERROR(SHUTTER_GVF_MISMATCH),
		VERSAL_PUF_ERROR(ERROR_SYN_DATA_ERROR),
		VERSAL_PUF_ERROR(IRO_FREQ_WRITE_MISMATCH),
		/* Regeneration */
		VERSAL_PUF_ERROR(ERROR_CHASH_NOT_PROGRAMMED),
		VERSAL_PUF_ERROR(ERROR_PUF_STATUS_DONE_TIMEOUT),
		VERSAL_PUF_ERROR(ERROR_INVALID_REGENERATION_TYPE),
		VERSAL_PUF_ERROR(ERROR_INVALID_PUF_OPERATION),
		VERSAL_PUF_ERROR(ERROR_REGENERATION_INVALID),
		VERSAL_PUF_ERROR(ERROR_REGEN_PUF_HD_INVALID),
		VERSAL_PUF_ERROR(ERROR_INVALID_READ_HD_INPUT),
		VERSAL_PUF_ERROR(ERROR_PUF_DONE_KEY_NT_RDY),
		VERSAL_PUF_ERROR(ERROR_PUF_DONE_ID_NT_RDY),
		VERSAL_PUF_ERROR(ERROR_PUF_ID_ZERO_TIMEOUT),
	};
	size_t error = 0;
	size_t index = 0;

	if (err <= ERROR_PUF_ID_ZERO_TIMEOUT && err >= ERROR_INVALID_PARAM) {
		index = err - ERROR_INVALID_PARAM;

		/* Spectre gadget protection: array index is external event */
		error = confine_array_index(index, ARRAY_SIZE(elist));
		if (elist[error].name)
			return elist[error].name;

		return "Invalid";
	}

	return "Unknown";
}

/*
 * Register the Physical Unclonable Function (prior operating with it)
 *
 * This must happen during the device provisioning phase and can be done from
 * the Secure World via this interface or from an earlier firmware.
 */
TEE_Result versal_puf_register(struct versal_puf_data *buf,
			       struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf = { };
	struct versal_mbox_mem request = {
		.alloc_len = sizeof(req),
		.len = sizeof(req),
		.buf = &req,
	};
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	struct versal_ipi_cmd arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].mem = request;
	arg.ibuf[1].mem = syndrome_data_addr;
	arg.ibuf[2].mem = hash_addr;
	arg.ibuf[3].mem = aux_addr;
	arg.ibuf[4].mem = puf_id_addr;
	arg.ibuf[5].mem = efuse_syn_data_addr;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_data_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(VERSAL_PUF_REGISTER);
	reg_pair_from_64(virt_to_phys(arg.ibuf[0].mem.buf),
			 &arg.data[2], &arg.data[1]);

	if (versal_mbox_notify(&arg, NULL, &err)) {
		EMSG("Versal, failed to register the PUF [%s]",
		     versal_puf_error(err));

		ret = TEE_ERROR_GENERIC;
	}

	/* Return the generated data */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));
	memcpy(&buf->chash, hash_addr.buf, sizeof(buf->chash));
	memcpy(&buf->aux, aux_addr.buf, sizeof(buf->aux));
	memcpy(buf->efuse_syn_data, efuse_syn_data_addr.buf,
	       sizeof(buf->efuse_syn_data));
	memcpy(buf->syndrome_data, syndrome_data_addr.buf,
	       sizeof(buf->syndrome_data));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

/*
 * Re-seed the PUF circuitry so it can re-generate the Key Encryption Key.
 *
 * Depending on the configuration options it might use eFused data instead of
 * the helper data provided via the interface.
 */
TEE_Result versal_puf_regenerate(struct versal_puf_data *buf,
				 struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf = { };
	struct versal_mbox_mem request = {
		.alloc_len = sizeof(req),
		.len = sizeof(req),
		.buf = &req,
	};
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	struct versal_ipi_cmd arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].mem = request;
	arg.ibuf[1].mem = syndrome_data_addr;
	arg.ibuf[2].mem = hash_addr;
	arg.ibuf[3].mem = aux_addr;
	arg.ibuf[4].mem = puf_id_addr;
	arg.ibuf[5].mem = efuse_syn_data_addr;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(VERSAL_PUF_REGENERATE);
	reg_pair_from_64(virt_to_phys(arg.ibuf[0].mem.buf),
			 &arg.data[2], &arg.data[1]);

	if (versal_mbox_notify(&arg, NULL, &err)) {
		EMSG("Versal, failed to regenerate the PUF [%s]",
		     versal_puf_error(err));

		ret = TEE_ERROR_GENERIC;
	}

	/* Return the updated PUF_ID */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

/*
 * Clear/Hide the PUF Unique ID
 *
 * The fully accessible (non-secret) Unique ID is generated from the PUF
 */
TEE_Result versal_puf_clear_id(void)
{
	struct versal_ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(VERSAL_PUF_CLEAR_ID);

	if (versal_mbox_notify(&arg, NULL, NULL)) {
		EMSG("Versal, failed to clear the PUF_ID");

		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/* Check that the API id is available to the client */
TEE_Result versal_puf_check_api(enum versal_puf_api id)
{
	struct versal_ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(VERSAL_PUF_API_FEATURES);
	arg.data[1] = id;

	if (versal_mbox_notify(&arg, NULL, NULL))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
