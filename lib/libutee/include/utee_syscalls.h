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
#ifndef UTEE_SYSCALLS_H
#define UTEE_SYSCALLS_H

#include <compiler.h>
#include <stddef.h>
#include <stdint.h>

#include <utee_types.h>
#include <tee_api_types.h>
#include <trace.h>

void utee_return(uint32_t ret) __noreturn;

void utee_log(const void *buf, size_t len);

void utee_panic(uint32_t code) __noreturn;

uint32_t utee_dummy(uint32_t *a);

uint32_t utee_dummy_7args(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
			  uint32_t a5, uint32_t a6, uint32_t a7);

uint32_t utee_nocall(void);

TEE_Result utee_get_property(enum utee_property prop, void *buf, uint32_t len);

TEE_Result utee_open_ta_session(const TEE_UUID *dest,
				uint32_t cancel_req_to, uint32_t param_types,
				TEE_Param params[4], TEE_TASessionHandle *sess,
				uint32_t *ret_orig);

TEE_Result utee_close_ta_session(TEE_TASessionHandle sess);

TEE_Result utee_invoke_ta_command(TEE_TASessionHandle sess,
				  uint32_t cancel_req_to, uint32_t cmd_id,
				  uint32_t param_types, TEE_Param params[4],
				  uint32_t *ret_orig);

TEE_Result utee_check_access_rights(uint32_t flags, const void *buf,
				    size_t len);

TEE_Result utee_get_cancellation_flag(bool *cancel);

TEE_Result utee_unmask_cancellation(bool *old_mask);

TEE_Result utee_mask_cancellation(bool *old_mask);

TEE_Result utee_wait(uint32_t timeout);

TEE_Result utee_get_time(enum utee_time_category cat, TEE_Time *time);

TEE_Result utee_set_ta_time(const TEE_Time *time);

TEE_Result utee_cryp_state_alloc(uint32_t algo, uint32_t op_mode,
				 uint32_t key1, uint32_t key2,
				 uint32_t *state);
TEE_Result utee_cryp_state_copy(uint32_t dst, uint32_t src);
TEE_Result utee_cryp_state_free(uint32_t state);

/* iv and iv_len are ignored for some algorithms */
TEE_Result utee_hash_init(uint32_t state, const void *iv, size_t iv_len);
TEE_Result utee_hash_update(uint32_t state, const void *chunk,
			    size_t chunk_size);
TEE_Result utee_hash_final(uint32_t state, const void *chunk,
			   size_t chunk_size, void *hash, uint32_t *hash_len);

TEE_Result utee_cipher_init(uint32_t state, const void *iv, size_t iv_len);
TEE_Result utee_cipher_update(uint32_t state, const void *src, size_t src_len,
			      void *dest, uint32_t *dest_len);
TEE_Result utee_cipher_final(uint32_t state, const void *src, size_t src_len,
			     void *dest, uint32_t *dest_len);

/* Generic Object Functions */
TEE_Result utee_cryp_obj_get_info(uint32_t obj, TEE_ObjectInfo *info);
TEE_Result utee_cryp_obj_restrict_usage(uint32_t obj, uint32_t usage);
TEE_Result utee_cryp_obj_get_attr(uint32_t obj, uint32_t attr_id,
				  void *buffer, uint32_t *size);

/* Transient Object Functions */
TEE_Result utee_cryp_obj_alloc(TEE_ObjectType type, uint32_t max_size,
			       uint32_t *obj);
TEE_Result utee_cryp_obj_close(uint32_t obj);
TEE_Result utee_cryp_obj_reset(uint32_t obj);
TEE_Result utee_cryp_obj_populate(uint32_t obj, TEE_Attribute *attrs,
				  uint32_t attr_count);
TEE_Result utee_cryp_obj_copy(uint32_t dst_obj, uint32_t src_obj);

TEE_Result utee_cryp_obj_generate_key(uint32_t obj, uint32_t key_size,
				      const TEE_Attribute *params,
				      uint32_t param_count);

TEE_Result utee_cryp_derive_key(uint32_t state, const TEE_Attribute *params,
				uint32_t param_count, uint32_t derived_key);

TEE_Result utee_cryp_random_number_generate(void *buf, size_t blen);

TEE_Result utee_authenc_init(uint32_t state, const void *nonce,
			     size_t nonce_len, size_t tag_len, size_t aad_len,
			     size_t payload_len);
TEE_Result utee_authenc_update_aad(uint32_t state, const void *aad_data,
				   size_t aad_data_len);
TEE_Result utee_authenc_update_payload(uint32_t state, const void *src_data,
				       size_t src_len, void *dest_data,
				       uint32_t *dest_len);
TEE_Result utee_authenc_enc_final(uint32_t state, const void *src_data,
				  size_t src_len, void *dest_data,
				  uint32_t *dest_len, void *tag,
				  uint32_t *tag_len);
TEE_Result utee_authenc_dec_final(uint32_t state, const void *src_data,
				  size_t src_len, void *dest_data,
				  uint32_t *dest_len, const void *tag,
				  size_t tag_len);

TEE_Result utee_asymm_operate(uint32_t state, const TEE_Attribute *params,
			      uint32_t num_params, const void *src_data,
			      size_t src_len, void *dest_data,
			      uint32_t *dest_len);

TEE_Result utee_asymm_verify(uint32_t state,
			     const TEE_Attribute *params, uint32_t num_params,
			     const void *data, size_t data_len, const void *sig,
			     size_t sig_len);

/* Persistant Object Functions */
TEE_Result utee_storage_obj_open(uint32_t storage_id, void *object_id,
				 uint32_t object_id_len, uint32_t flags,
				 TEE_ObjectHandle *obj);

TEE_Result utee_storage_obj_create(uint32_t storage_id, void *object_id,
				   uint32_t object_id_len, uint32_t flags,
				   TEE_ObjectHandle attr, const void *data,
				   uint32_t len, TEE_ObjectHandle *obj);

TEE_Result utee_storage_obj_del(TEE_ObjectHandle obj);

TEE_Result utee_storage_obj_rename(TEE_ObjectHandle obj, const void *new_obj_id,
				   size_t new_obj_id_len);

/* Persistent Object Enumeration Functions */
TEE_Result utee_storage_alloc_enum(TEE_ObjectEnumHandle *obj_enum);

TEE_Result utee_storage_free_enum(TEE_ObjectEnumHandle obj_enum);

TEE_Result utee_storage_reset_enum(TEE_ObjectEnumHandle obj_enum);

TEE_Result utee_storage_start_enum(TEE_ObjectEnumHandle obj_enum,
				   uint32_t storage_id);

TEE_Result utee_storage_next_enum(TEE_ObjectEnumHandle obj_enum,
				  TEE_ObjectInfo *info, void *obj_id,
				  uint32_t *len);

/* Data Stream Access Functions */
TEE_Result utee_storage_obj_read(TEE_ObjectHandle obj, void *data, size_t len,
				 uint32_t *count);

TEE_Result utee_storage_obj_write(TEE_ObjectHandle obj, const void *data,
				  size_t len);

TEE_Result utee_storage_obj_trunc(TEE_ObjectHandle obj, size_t len);

TEE_Result utee_storage_obj_seek(TEE_ObjectHandle obj, int32_t offset,
				 TEE_Whence whence);

TEE_Result utee_se_service_open(
		TEE_SEServiceHandle *seServiceHandle);

TEE_Result utee_se_service_close(
		TEE_SEServiceHandle seServiceHandle);

TEE_Result utee_se_service_get_readers(
		TEE_SEServiceHandle seServiceHandle,
		TEE_SEReaderHandle *r, size_t *len);

TEE_Result utee_se_reader_get_prop(TEE_SEReaderHandle r,
				TEE_SEReaderProperties *p);

TEE_Result utee_se_reader_get_name(TEE_SEReaderHandle r,
		char *name, size_t *name_len);

TEE_Result utee_se_reader_open_session(TEE_SEReaderHandle r,
		TEE_SESessionHandle *s);

TEE_Result utee_se_reader_close_sessions(TEE_SEReaderHandle r);

TEE_Result utee_se_session_is_closed(TEE_SESessionHandle s);

TEE_Result utee_se_session_get_atr(TEE_SESessionHandle s,
		void *atr, size_t *atr_len);

TEE_Result utee_se_session_open_channel(TEE_SESessionHandle s,
		bool is_logical, TEE_SEAID *aid, TEE_SEChannelHandle *c);

TEE_Result utee_se_session_close(TEE_SESessionHandle s);

TEE_Result utee_se_channel_select_next(TEE_SEChannelHandle c);

TEE_Result utee_se_channel_get_select_resp(TEE_SEChannelHandle c,
	void *resp, size_t *resp_len);

TEE_Result utee_se_channel_transmit(TEE_SEChannelHandle c,
	void *cmd, size_t cmd_len, void *resp, size_t *resp_len);

TEE_Result utee_se_channel_close(TEE_SEChannelHandle c);

TEE_Result utee_cache_operation(void *va, size_t l,
				enum utee_cache_operation op);

#endif /* UTEE_SYSCALLS_H */
