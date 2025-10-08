// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Marvell
 */

#include <trace.h>

#include "mrvl_ehsm_cryp.h"
#include "ehsm-aes.h"
#include "ehsm.h"
#include <string.h>

static struct mutex ehsm_lock = MUTEX_INITIALIZER;

static struct mrvl_ehsm_engine engine = {
	.lock = &ehsm_lock,
	.context_count = 0
};

void mrvl_ehsm_cryp_lock(void)
{
	mutex_lock(engine.lock);
}

void mrvl_ehsm_cryp_unlock(void)
{
	mutex_unlock(engine.lock);
}

#ifdef CFG_EHSM_CONTEXT_STORE_SUPPORT
bool mrvl_ehsm_aes_cryp_allowed(void)
{
	bool cryp_allowed = false;

	mutex_lock(engine.lock);
	if (engine.context_count < EHSM_AES_MAX_CONTEXT_SLOTS) {
		cryp_allowed = true;
		engine.context_count++;
	}
	mutex_unlock(engine.lock);

	return cryp_allowed;
}

void mrvl_ehsm_aes_cryp_release(void)
{
	mutex_lock(engine.lock);
	if (engine.context_count)
		engine.context_count--;
	mutex_unlock(engine.lock);
}

TEE_Result  mrvl_ehsm_aes_context_store(uint32_t *pcontext_id)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t *ehsm_pcontext = NULL;
	enum sec_return ret = SEC_NO_ERROR;

	ehsm_pcontext = mem_alloc(sizeof(uint32_t));
	if (!ehsm_pcontext) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ret = ehsm_context_store(&engine.ehandle, CONTEXT_AES,
				 ehsm_pcontext, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes context store failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes context store passed, ret: %d\n", ret);
	}

	*pcontext_id = *ehsm_pcontext;

	free(ehsm_pcontext);
out:
	return res;
}

TEE_Result  mrvl_ehsm_aes_context_load(uint32_t context_id)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;

	ret = ehsm_context_load(&engine.ehandle, CONTEXT_AES, context_id, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes context load failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes context load passed, ret: %d\n", ret);
	}

	return res;
}

TEE_Result  mrvl_ehsm_aes_context_release(uint32_t context_id)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;

	ret = ehsm_context_release(&engine.ehandle, CONTEXT_AES,
				   context_id, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes context free failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes context free passed, ret: %d\n", ret);
	}

	return res;
}
#else
bool ehsm_aes_engine_initialized;

bool mrvl_ehsm_aes_cryp_allowed(void)
{
	bool cryp_allowed = false;

	mutex_lock(engine.lock);
	if (!ehsm_aes_engine_initialized) {
		ehsm_aes_engine_initialized = true;
		cryp_allowed = true;
	}
	mutex_unlock(engine.lock);

	return cryp_allowed;
}

void mrvl_ehsm_aes_cryp_release(void)
{
	mutex_lock(engine.lock);
	ehsm_aes_engine_initialized = false;
	mutex_unlock(engine.lock);
}

TEE_Result  mrvl_ehsm_aes_context_store(uint32_t *pcontext_id __maybe_unused)
{
	return TEE_SUCCESS;
}

TEE_Result  mrvl_ehsm_aes_context_load(uint32_t context_id __maybe_unused)
{
	return TEE_SUCCESS;
}

TEE_Result  mrvl_ehsm_aes_context_release(uint32_t context_id __maybe_unused)
{
	return TEE_SUCCESS;
}
#endif

void *mem_alloc(size_t size)
{
	void *ptr = NULL;
	size_t alloc_size = 0;

	if (ROUNDUP_OVERFLOW(size, EHSM_ALIGNMENT, &alloc_size))
		return NULL;

	ptr = memalign(EHSM_ALIGNMENT, alloc_size);
	if (!ptr)
		return NULL;

	memset(ptr, 0, size);

	return ptr;
}

TEE_Result mrvl_ehsm_cryp_initialize(void)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;

	ret = ehsm_initialize(&engine.ehandle, EHSM_CRYPTO_MAILBOX);
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
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;

	ret = mrvl_ehsm_cryp_initialize();
	if (ret)
		goto out;

	ret = ehsm_aes_zeroize(&engine.ehandle);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes zeroize failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes zeroize passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_key(&engine.ehandle, key_size * 8, key_data, 0, 0);
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

	ret = ehsm_aes_gcm_init(&engine.ehandle, !is_dec, aad_size, tag_size,
				iv_size, iv_data, endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes gcm init failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes gcm init passed, ret: %d\n", ret);
	}

out:
	return res;
}

TEE_Result mrvl_ehsm_aes_gcm_update_payload(const void *src, uint32_t src_len,
					    void *dst, uint32_t dst_len,
					    bool new)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;
	uint32_t len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&engine.ehandle, src, dst, len, 0, new, 0, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process passed, ret: %d\n", ret);
	}

	return res;
}

TEE_Result mrvl_ehsm_aes_gcm_final(const void *src, uint32_t src_len,
				   void *dst, uint32_t dst_len, bool new)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;
	uint32_t len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&engine.ehandle, src, dst, len, 0, new, 1, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process passed, ret: %d\n", ret);
	}

	return res;
}

TEE_Result mrvl_ehsm_aes_init(uint8_t aes_mode, bool is_dec,
			      void *key_data, size_t key_size,
			      void *key2_data, size_t key2_size,
			      uint8_t *iv_data, bool endian_swap)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;

	ret = mrvl_ehsm_cryp_initialize();
	if (ret)
		goto out;

	ret = ehsm_aes_zeroize(&engine.ehandle);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes zeroize failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes zeroize passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_key(&engine.ehandle, key_size * 8, key_data, 0,
				endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM load key failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM load key passed, ret: %d\n", ret);
	}

	if (key2_size) {
		ret = ehsm_aes_load_key(&engine.ehandle, key2_size * 8,
					key2_data, 1, endian_swap);
		if (ret != SEC_NO_ERROR) {
			EMSG("eHSM load key2 failed, ret: %d\n", ret);
			res = TEE_ERROR_GENERIC;
			goto out;
		} else {
			DMSG("eHSM load key2 passed, ret: %d\n", ret);
		}
	}

	ret = ehsm_aes_init(&engine.ehandle, !is_dec, key_size * 8, aes_mode, 0,
			    endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes init failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes init passed, ret: %d\n", ret);
	}

	ret = ehsm_aes_load_iv(&engine.ehandle, iv_data, endian_swap);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes load iv failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	} else {
		DMSG("eHSM aes load iv passed, ret: %d\n", ret);
	}

out:
	return res;
}

TEE_Result mrvl_ehsm_aes_update_payload(const void *src, uint32_t src_len,
					void *dst, uint32_t dst_len,
					bool new, bool final)
{
	TEE_Result res = TEE_SUCCESS;
	enum sec_return ret = SEC_NO_ERROR;
	uint32_t len = MIN(src_len, dst_len);

	ret = ehsm_aes_process(&engine.ehandle, src, dst, len, 0, new, final, 0,
			       NULL, NULL);
	if (ret != SEC_NO_ERROR) {
		EMSG("eHSM aes process update failed, ret: %d\n", ret);
		res = TEE_ERROR_GENERIC;
	} else {
		DMSG("eHSM aes process update passed, ret: %d\n", ret);
	}

	return res;
}
