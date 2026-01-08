/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Missing Link Electronics, Inc.
 */

#ifndef __DRIVERS_VERSAL_OCP_H
#define __DRIVERS_VERSAL_OCP_H

#include <stdint.h>
#include <tee_api_types.h>

/*
 * The following symbols/types/definitions are taken from AMD/Xilinx
 * embeddedsw::lib/sw_services/xilocp/src/common/xocp_common.h
 * v2024.2
 */

#define VERSAL_OCP_PCR_SIZE_BYTES		48

#define VERSAL_OCP_DME_DEVICE_ID_SIZE_WORDS	12
#define VERSAL_OCP_DME_NONCE_SIZE_WORDS		8
#define VERSAL_OCP_DME_NONCE_SIZE_BYTES \
	(VERSAL_OCP_DME_NONCE_SIZE_WORDS << 2)
#define VERSAL_OCP_DME_MEASURE_SIZE_WORDS	12

#define VERSAL_OCP_ECC_P384_SIZE_WORDS		12
#define VERSAL_OCP_ECC_P384_SIZE_BYTES \
	(VERSAL_OCP_ECC_P384_SIZE_WORDS << 2)

#define VERSAL_OCP_SHA3_LEN_IN_BYTES		48

enum versal_ocp_hwpcr {
	VERSAL_OCP_PCR_0 = 0,
	VERSAL_OCP_PCR_1,
	VERSAL_OCP_PCR_2,
	VERSAL_OCP_PCR_3,
	VERSAL_OCP_PCR_4,
	VERSAL_OCP_PCR_5,
	VERSAL_OCP_PCR_6,
	VERSAL_OCP_PCR_7
};

struct versal_ocp_hwpcr_event {
	uint8_t pcr_no;
	uint8_t hash[VERSAL_OCP_SHA3_LEN_IN_BYTES];
	uint8_t pcr_value[VERSAL_OCP_SHA3_LEN_IN_BYTES];
};

struct versal_ocp_hwpcr_log_info {
	uint32_t remaining_hwpcr_events;
	uint32_t total_hwpcr_log_events;
	uint32_t overflow_cnt_since_last_rd;
	uint32_t hwpcr_events_read;
};

struct versal_ocp_pcr_measurement {
	uint32_t event_id;
	uint32_t version;
	uint32_t data_length;
	uint8_t hash[VERSAL_OCP_PCR_SIZE_BYTES];
	uint8_t measured[VERSAL_OCP_PCR_SIZE_BYTES];
};

struct versal_ocp_dme {
	uint32_t device_id[VERSAL_OCP_DME_DEVICE_ID_SIZE_WORDS];
	uint32_t nonce[VERSAL_OCP_DME_NONCE_SIZE_WORDS];
	uint32_t measurement[VERSAL_OCP_DME_MEASURE_SIZE_WORDS];
};

struct versal_ocp_dme_response {
	struct versal_ocp_dme dme;
	uint32_t dme_signature_r[VERSAL_OCP_ECC_P384_SIZE_WORDS];
	uint32_t dme_signature_s[VERSAL_OCP_ECC_P384_SIZE_WORDS];
};

enum versal_ocp_dev_key {
	VERSAL_OCP_DEVIK = 0,
	VERSAL_OCP_DEVAK,
	VERSAL_OCP_KEY_WRAP_DEVAK
};

enum versal_ocp_status {
	VERSAL_OCP_PCR_ERR_PCR_SELECT	= 0x02,
	VERSAL_OCP_PCR_ERR_NOT_COMPLETED,
	VERSAL_OCP_PCR_ERR_OPERATION,
	VERSAL_OCP_PCR_ERR_IN_UPDATE_LOG,
	VERSAL_OCP_PCR_ERR_IN_GET_PCR,
	VERSAL_OCP_PCR_ERR_IN_GET_PCR_LOG,
	VERSAL_OCP_PCR_ERR_INVALID_LOG_READ_REQUEST,
	VERSAL_OCP_PCR_ERR_MEASURE_IDX_SELECT,
	VERSAL_OCP_PCR_ERR_SWPCR_CONFIG_NOT_RECEIVED,
	VERSAL_OCP_PCR_ERR_INSUFFICIENT_BUF_MEM,
	VERSAL_OCP_PCR_ERR_SWPCR_DUP_EXTEND,
	VERSAL_OCP_PCR_ERR_DATA_IN_INVALID_MEM,

	VERSAL_OCP_DICE_CDI_PARITY_ERROR = 0x20,
	VERSAL_OCP_DME_ERR,
	VERSAL_OCP_DME_ROM_ERROR,
	VERSAL_OCP_ERR_DEVIK_NOT_READY,
	VERSAL_OCP_ERR_DEVAK_NOT_READY,
	VERSAL_OCP_ERR_INVALID_DEVAK_REQ,
	VERSAL_OCP_DICE_CDI_SEED_ZERO,
	VERSAL_OCP_ERR_GLITCH_DETECTED,
	VERSAL_OCP_ERR_CHUNK_BOUNDARY_CROSSED,
	VERSAL_OCP_ERR_SECURE_EFUSE_CONFIG,
	VERSAL_OCP_ERR_SECURE_TAP_CONFIG,
	VERSAL_OCP_ERR_SECURE_STATE_MEASUREMENT,
	VERSAL_OCP_ERR_DME_RESP_ALREADY_GENERATED,
	VERSAL_OCP_ERR_DME_RESP_NOT_GENERATED,
	VERSAL_OCP_ERR_PUB_KEY_NOT_AVAIL,
	VERSAL_OCP_ERR_INVALID_ATTEST_BUF_SIZE,
	VERSAL_OCP_ERR_SECURE_PPK_CONFIG,
	VERSAL_OCP_ERR_SECURE_SPK_REVOKE_CONFIG,
	VERSAL_OCP_ERR_SECURE_OTHER_REVOKE_CONFIG,
	VERSAL_OCP_ERR_SECURE_MISC_CONFIG,
	VERSAL_OCP_ERR_READ_PPK_CONFIG,
	VERSAL_OCP_ERR_READ_SPK_REVOKE_CONFIG,
	VERSAL_OCP_ERR_READ_OTHER_REVOKE_CONFIG,
	VERSAL_OCP_ERR_IN_EXTEND_PPK_CONFIG,
	VERSAL_OCP_ERR_IN_EXTEND_SPK_REVOKE_CONFIG,
	VERSAL_OCP_ERR_IN_EXTEND_OTHER_REVOKE_CONFIG,
	VERSAL_OCP_ERR_IN_EXTEND_MISC_CONFIG,
	VERSAL_OCP_ERR_IN_EXTEND_SECURE_STATE_CONFIG,
	VERSAL_OCP_ERR_IN_MEMCPY
};

#define VERSAL_OCP_STATUS_MASK 0xff

/*
 * The following symbols/types/definitions are taken from AMD/Xilinx
 * embeddedsw::
 * lib/sw_services/xilsecure/src/server/core/key_unwrap/xsecure_plat_rsa.h
 * v2024.2
 */

#define VERSAL_SECURE_RSA_3072_SIZE_WORDS 96
#define VERSAL_SECURE_RSA_KEY_GEN_SIZE_IN_BYTES \
	(VERSAL_SECURE_RSA_3072_SIZE_WORDS * 4)
#define VERSAL_SECURE_RSA_KEY_GEN_SIZE_IN_WORDS \
	(VERSAL_SECURE_RSA_KEY_GEN_SIZE_IN_BYTES / 4)
#define VERSAL_SECURE_RSA_PUB_EXP_SIZE 4

struct versal_secure_rsapubkey {
	uint8_t mod[VERSAL_SECURE_RSA_KEY_GEN_SIZE_IN_BYTES];
	uint32_t pub_exp[VERSAL_SECURE_RSA_KEY_GEN_SIZE_IN_WORDS];
};

/*
 * The following functions shall mimic the XilOCP client side interface from
 * AMD/Xilinx embeddedsw::lib/sw_services/xilocp/src/client/xocp_client.h
 * v2024.2
 */

uint32_t versal_ocp_plm_status_get(void);
uint32_t versal_ocp_status_get(void);

TEE_Result versal_ocp_extend_hwpcr(enum versal_ocp_hwpcr pcr_num,
				   void *data, uint32_t data_size);
TEE_Result versal_ocp_get_hwpcr(uint32_t pcr_mask,
				void *pcr_buf, uint32_t pcr_buf_size);
TEE_Result versal_ocp_get_hwpcr_log(struct versal_ocp_hwpcr_event *events,
				    uint32_t events_size,
				    struct versal_ocp_hwpcr_log_info *loginfo);

TEE_Result versal_ocp_extend_swpcr(uint32_t pcr_num,
				   void *data, uint32_t data_size,
				   uint32_t measurement_idx, bool overwrite);
TEE_Result versal_ocp_get_swpcr(uint32_t pcr_mask,
				void *pcr_buf, uint32_t pcr_buf_size);
TEE_Result versal_ocp_get_swpcr_data(uint32_t pcr_num, uint32_t measurement_idx,
				     uint32_t data_start_idx,
				     void *data, uint32_t data_size,
				     uint32_t *data_returned);
TEE_Result
versal_ocp_get_swpcr_log(uint32_t pcr_num,
			 struct versal_ocp_pcr_measurement *measurements,
			 uint32_t measurements_size,
			 uint32_t *measurements_count);

TEE_Result versal_ocp_gen_dme_resp(void *nonce, uint32_t nonce_size,
				   struct versal_ocp_dme_response *response);
TEE_Result versal_ocp_get_x509_cert(void *cert, uint32_t cert_size,
				    uint32_t *actual_cert_size,
				    enum versal_ocp_dev_key dev_key_sel,
				    bool is_csr);
TEE_Result versal_ocp_attest_with_devak(void *hash, uint32_t hash_size,
					void *signature,
					uint32_t signature_size);
TEE_Result versal_ocp_attest_with_key_wrap_devak(void *attest_buf,
						 uint32_t attest_buf_size,
						 uint32_t pub_key_offset,
						 void *signature,
						 uint32_t signature_size);
TEE_Result versal_ocp_gen_shared_secret_with_devak(void *pub_key,
						   uint32_t pub_key_size,
						   void *shared_secret,
						   uint32_t shared_secret_size);

#endif /* __DRIVERS_VERSAL_OCP_H */
