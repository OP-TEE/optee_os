/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_PROCESSING_H
#define PKCS11_TA_PROCESSING_H

#include <pkcs11_attributes.h>
#include <tee_internal_api.h>

struct pkcs11_client;
struct pkcs11_session;
struct pkcs11_object;
struct active_processing;

/*
 * Entry points from PKCS11 TA invocation commands
 */

enum pkcs11_rc entry_generate_secret(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_generate_key_pair(struct pkcs11_client *client,
				       uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc entry_processing_init(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function);

enum pkcs11_rc entry_processing_step(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params,
				     enum processing_func function,
				     enum processing_step step);

enum pkcs11_rc entry_processing_key(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params,
				    enum processing_func function);

enum pkcs11_rc entry_release_active_processing(struct pkcs11_client *client,
					       uint32_t ptypes,
					       TEE_Param *params);

/*
 * Util
 */
size_t get_object_key_bit_size(struct pkcs11_object *obj);

void release_active_processing(struct pkcs11_session *session);

enum pkcs11_rc alloc_get_tee_attribute_data(TEE_ObjectHandle tee_obj,
					    uint32_t attribute,
					    void **data, size_t *size);

enum pkcs11_rc tee2pkcs_add_attribute(struct obj_attrs **head,
				      uint32_t pkcs11_id,
				      TEE_ObjectHandle tee_obj,
				      uint32_t tee_id);

/*
 * Symmetric crypto algorithm specific functions
 */
bool processing_is_tee_symm(uint32_t proc_id);

enum pkcs11_rc init_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *key);

enum pkcs11_rc step_symm_operation(struct pkcs11_session *session,
				   enum processing_func function,
				   enum processing_step step,
				   uint32_t ptypes, TEE_Param *params);

enum pkcs11_rc tee_init_ctr_operation(struct active_processing *processing,
				      void *proc_params, size_t params_size);

enum pkcs11_rc derive_key_by_symm_enc(struct pkcs11_session *session,
				      void **out_buf, uint32_t *out_sz);

/* Digest specific functions */
bool processing_is_tee_digest(enum pkcs11_mechanism_id mecha_id);

enum pkcs11_rc
init_digest_operation(struct pkcs11_session *session,
		      struct pkcs11_attribute_head *proc_params);

enum pkcs11_rc step_digest_operation(struct pkcs11_session *session,
				     enum processing_step step,
				     struct pkcs11_object *obj,
				     uint32_t ptypes, TEE_Param *params);

#endif /*PKCS11_TA_PROCESSING_H*/
