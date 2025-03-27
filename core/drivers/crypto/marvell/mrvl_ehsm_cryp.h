/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Marvell
 */

#ifndef __MRVL_EHSM_CRYP_H__
#define __MRVL_EHSM_CRYP_H__
#include <mempool.h>
#include <tee_api_types.h>

#include "ehsm-hal.h"
#include "ehsm.h"

enum mrvl_cryp_algo_mode {
	MRVL_CRYP_MODE_AES_ECB,
	MRVL_CRYP_MODE_AES_CBC,
	MRVL_CRYP_MODE_AES_CTR,
	MRVL_CRYP_MODE_AES_XTS,
	MRVL_CRYP_MODE_AES_KEY_WRAP,
	MRVL_CRYP_MODE_AES_CFB,
	MRVL_CRYP_MODE_AES_OFB
};

struct mrvl_cryp_context {
	bool op_enc_dec;

	uint8_t *key;
	size_t key_len;

	uint8_t *key2;
	size_t key2_len;

	uint8_t *aad_data;
	size_t aad_cur_idx;
	size_t aad_len;

	uint8_t *iv_data;
	size_t iv_len;

	size_t tag_len;

	bool is_new;
};

#define EHSM_MAILBOX0 0
#define EHSM_MAILBOX1 1
#define EHSM_MAILBOX2 2

/*
 * Handle related to CRYP instance
 * @ehandle - handle for HW instance
 * @lock - lock protect cryp HW instance access
 */

struct mrvl_ehsm_cryp {
	struct ehsm_handle ehandle;
	struct mutex *lock; //lock cryp instance
};

void mrvl_ehsm_aes_context_init(void);
void mrvl_ehsm_aes_context_release(void);
bool mrvl_ehsm_aes_in_use(void);

TEE_Result mrvl_ehsm_cryp_initialize(void);
TEE_Result mrvl_ehsm_aes_gcm_init(bool is_dec, void *key_data, size_t key_size,
				  uint32_t aad_size, uint32_t tag_size,
				  uint32_t iv_size, void *iv_data,
				  bool endian_swap);

TEE_Result mrvl_ehsm_aes_gcm_update_payload(const void *src, uint32_t src_len,
					    void *dest, uint32_t dst_len,
					    bool new);
TEE_Result mrvl_ehsm_aes_gcm_final(const void *src, uint32_t src_len,
				   void *dest, uint32_t dst_len, bool new);

TEE_Result mrvl_ehsm_aes_init(uint8_t aes_mode, bool is_dec,
			      void *key_data, size_t key_size,
			      void *key2_data, size_t key2_size,
			      uint8_t *iv_data, bool endian_swap);
TEE_Result mrvl_ehsm_aes_update_payload(const void *src, uint32_t src_len,
					void *dst, uint32_t dst_len,
					bool new, bool final);
#endif /*__MRVL_EHSM_CRYP_H__*/
