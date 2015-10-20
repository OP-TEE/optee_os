/*
* Copyright (c) 2014, STMicroelectronics International N.V.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef TEE_SVC_CRYP_H
#define TEE_SVC_CRYP_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager_unpg.h>

TEE_Result tee_svc_cryp_obj_get_info(uint32_t obj, TEE_ObjectInfo *info);
TEE_Result tee_svc_cryp_obj_restrict_usage(uint32_t obj, uint32_t usage);
TEE_Result tee_svc_cryp_obj_get_attr(uint32_t obj, uint32_t attr_id,
			     void *buffer, uint32_t *size);

TEE_Result tee_svc_cryp_obj_alloc(TEE_ObjectType obj_type,
			  uint32_t max_key_size, uint32_t *obj);
TEE_Result tee_svc_cryp_obj_close(uint32_t obj);
TEE_Result tee_svc_cryp_obj_reset(uint32_t obj);
TEE_Result tee_svc_cryp_obj_populate(uint32_t obj,
		struct abi_user32_attribute *usr_attrs, uint32_t attr_count);
TEE_Result tee_svc_cryp_obj_copy(uint32_t dst_obj, uint32_t src_obj);
TEE_Result tee_svc_obj_generate_key(uint32_t obj, uint32_t key_size,
			    const struct abi_user32_attribute *usr_params,
			    uint32_t param_count);

TEE_Result tee_svc_cryp_state_alloc(uint32_t algo, uint32_t op_mode,
			    uint32_t key1, uint32_t key2,
			    uint32_t *state);
TEE_Result tee_svc_cryp_state_copy(uint32_t dst, uint32_t src);
TEE_Result tee_svc_cryp_state_free(uint32_t state);
void tee_cryp_free_states(struct tee_ta_ctx *ctx);

/* iv and iv_len are ignored for hash algorithms */
TEE_Result tee_svc_hash_init(uint32_t state, const void *iv, size_t iv_len);
TEE_Result tee_svc_hash_update(uint32_t state, const void *chunk,
		       size_t chunk_size);
TEE_Result tee_svc_hash_final(uint32_t state, const void *chunk,
		      size_t chunk_size, void *hash, uint32_t *hash_len);

TEE_Result tee_svc_cipher_init(uint32_t state, const void *iv, size_t iv_len);
TEE_Result tee_svc_cipher_update(uint32_t state, const void *src,
			 size_t src_len, void *dest, uint32_t *dest_len);
TEE_Result tee_svc_cipher_final(uint32_t state, const void *src,
			size_t src_len, void *dest, uint32_t *dest_len);

TEE_Result tee_svc_cryp_derive_key(uint32_t state,
			const struct abi_user32_attribute *usr_params,
			uint32_t param_count, uint32_t derived_key);

TEE_Result tee_svc_cryp_random_number_generate(void *buf, size_t blen);

TEE_Result tee_svc_authenc_init(uint32_t state, const void *nonce,
			size_t nonce_len, size_t tag_len,
			size_t aad_len, size_t payload_len);
TEE_Result tee_svc_authenc_update_aad(uint32_t state, const void *aad_data,
			      size_t aad_data_len);
TEE_Result tee_svc_authenc_update_payload(uint32_t state, const void *src_data,
				  size_t src_len, void *dest_data,
				  uint32_t *dest_len);
TEE_Result tee_svc_authenc_enc_final(uint32_t state, const void *src_data,
			     size_t src_len, void *dest_data,
			     uint32_t *dest_len, void *tag,
			     uint32_t *tag_len);
TEE_Result tee_svc_authenc_dec_final(uint32_t state, const void *src_data,
			     size_t src_len, void *dest_data,
			     uint32_t *dest_len, const void *tag,
			     size_t tag_len);

TEE_Result tee_svc_asymm_operate(uint32_t state,
			const struct abi_user32_attribute *usr_params,
			uint32_t num_params, const void *src_data,
			size_t src_len, void *dest_data, uint32_t *dest_len);
TEE_Result tee_svc_asymm_verify(uint32_t state,
			const struct abi_user32_attribute *usr_params,
			uint32_t num_params, const void *data,
			size_t data_len, const void *sig, size_t sig_len);

#endif /* TEE_SVC_CRYP_H */
