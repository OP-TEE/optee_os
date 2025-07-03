// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Marvell
 */

#include <trace.h>

#include "mrvl_ehsm_cryp.h"
#include "ehsm-aes.h"

static struct mutex ehsm_lock = MUTEX_INITIALIZER;

static struct mrvl_ehsm_cryp cryp = {
	.lock = &ehsm_lock
};

bool ehsm_aes_initialized;

void mrvl_ehsm_aes_context_init(void)
{
	mutex_lock(cryp.lock);
	ehsm_aes_initialized = true;
	mutex_unlock(cryp.lock);
}

void mrvl_ehsm_aes_context_release(void)
{
	mutex_lock(cryp.lock);
	ehsm_aes_initialized = false;
	mutex_unlock(cryp.lock);
}

bool mrvl_ehsm_aes_in_use(void)
{
	bool val;

	mutex_lock(cryp.lock);
	val = ehsm_aes_initialized;
	mutex_unlock(cryp.lock);

	return val;
}

TEE_Result mrvl_ehsm_cryp_initialize(void)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;

	ret = ehsm_initialize2(&cryp.ehandle, EHSM_CRYPTO_MAILBOX);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes to initialize failed, ret : %#" PRIx32, ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes to initialize passed, ret : %#" PRIx32, ret);
	}

	return res;
}

TEE_Result mrvl_ehsm_aes_gcm_init(bool is_dec, void *key_data, size_t key_size,
				  uint32_t aad_size, uint32_t tag_size,
				  uint32_t iv_size, void *iv_data,
				  bool endian_swap)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(cryp.lock);

	ret = mrvl_ehsm_cryp_initialize();
	if (ret)
		goto out;

	ret = ehsm_aes_zeroize(&cryp.ehandle);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes zeroize failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes zeroize passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_key(&cryp.ehandle, key_size * 8, key_data, 0, 0);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM load key failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM load key passed, ret: %d\n", ret);
	}

	/* Special case (iv_size = 0) to capture a 12-bytes input IV. */
	if (iv_size == 12)
		iv_size = 0;

	ret = ehsm_aes_gcm_init(&cryp.ehandle, !is_dec, aad_size, tag_size,
				iv_size, iv_data, endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes gcm init failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes gcm init passed, ret: %d\n", ret);
	}

out:
	mutex_unlock(cryp.lock);

	return res;
}

TEE_Result mrvl_ehsm_aes_gcm_update_payload(const void *src, uint32_t src_len,
					    void *dst, uint32_t dst_len,
					    bool new)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;
	uint32_t len;

	mutex_lock(cryp.lock);

	len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&cryp.ehandle, src, dst, len, 0, new, 0, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process passed, ret: %d\n", ret);
	}

	mutex_unlock(cryp.lock);

	return res;
}

TEE_Result mrvl_ehsm_aes_gcm_final(const void *src, uint32_t src_len,
				   void *dst, uint32_t dst_len, bool new)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;
	uint32_t len;

	mutex_lock(cryp.lock);

	len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&cryp.ehandle, src, dst, len, 0, new, 1, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process passed, ret: %d\n", ret);
	}

	mutex_unlock(cryp.lock);

	return res;
}

TEE_Result mrvl_ehsm_aes_init(uint8_t aes_mode, bool is_dec,
			      void *key_data, size_t key_size,
			      void *key2_data, size_t key2_size,
			      uint8_t *iv_data, bool endian_swap)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(cryp.lock);

	ret = mrvl_ehsm_cryp_initialize();
	if (ret)
		goto out;

	ret = ehsm_aes_zeroize(&cryp.ehandle);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes zeroize failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes zeroize passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_key(&cryp.ehandle, key_size * 8, key_data, 0,
				endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM load key failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM load key passed, ret: %d\n", ret);
	}

	if (key2_size) {
		ret = ehsm_aes_load_key(&cryp.ehandle, key2_size * 8, key2_data,
					1, endian_swap);
		if (ret != SEC_NO_ERROR) {
			EMSG("eHSM load key2 failed, ret: %d\n", ret);
			res = TEE_ERROR_GENERIC;
			goto out;
		} else {
			DMSG("eHSM load key2 passed, ret: %d\n", ret);
		}
	}

	ret = ehsm_aes_init(&cryp.ehandle, !is_dec, key_size * 8, aes_mode, 0,
			    endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes init failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes init passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_iv(&cryp.ehandle, iv_data, endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes load iv failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes load iv passed, ret: %d\n", ret);
	}

out:
	mutex_unlock(cryp.lock);

	return res;
}

TEE_Result mrvl_ehsm_aes_update_payload(const void *src, uint32_t src_len,
					void *dst, uint32_t dst_len,
					bool new, bool final)
{
	enum sec_return ret;
	TEE_Result res = TEE_SUCCESS;
	uint32_t len;

	mutex_lock(cryp.lock);

	len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&cryp.ehandle, src, dst, len, 0, new, final, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process update failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process update passed, ret: %d\n", ret);
	}

	mutex_unlock(cryp.lock);

	return res;
}
