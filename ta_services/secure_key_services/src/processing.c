/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <sks_internal_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "object.h"
#include "pkcs11_token.h"
#include "pkcs11_attributes.h"
#include "processing.h"
#include "serializer.h"
#include "sks_helpers.h"

uint32_t entry_import_object(int teesess,
			     TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_attrs_head *head = NULL;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t obj_handle;

	/*
	 * Collect the arguments of the request
	 */

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t))
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &session_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_sks_attributes(&ctrlargs, &template))
		return SKS_BAD_PARAM;

	template_size = sizeof(*template) + template->blobs_size;

	/* Check session/token state against object import */
	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess) {
		rv = SKS_INVALID_SESSION;
		goto bail;
	}

	if (check_pkcs_session_processing_state(session,
						PKCS11_SESSION_READY)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto bail;
	}

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temorary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     SKS_FUNCTION_IMPORT);
	TEE_Free(template);
	template = NULL;
	if (rv)
		goto bail;

	/*
	 * Check target object attributes match target processing
	 * Check target object attributes match token state
	 */
	rv = check_created_attrs_against_processing(SKS_PROC_RAW_IMPORT, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * Execute the target processing and add value as attribute SKS_VALUE.
	 * Raw import => key value in clear already as attribute SKS_VALUE.
	 *
	 * Here we only check attribute that attribute SKS_VALUE is defined.
	 * TODO: check value size? check SKS_VALUE_LEN? check SKS_CHECKSUM.
	 */
	rv = get_attribute_ptr(head, SKS_VALUE, NULL, NULL);
	if (rv)
		goto bail;

	/*
	 * At this stage the object is almost created: all its attributes are
	 * referenced in @head, including the key value and are assume
	 * reliable. Now need to register it and get a handle for it.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialised buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

bail:
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

/*
 * Get the GPD TEE cipher operation parameters (mode, key size, algo)
 * from and SKS cipher operation.
 */
static uint32_t tee_operarion_params(struct pkcs11_session *session,
					struct sks_reference *proc_params,
					struct sks_object *sks_key,
					uint32_t function)
{
	uint32_t key_type;
	uint32_t algo;
	uint32_t mode;
	uint32_t size;
	TEE_Result res;
	void *value;
	size_t value_size;

	if (get_attribute_ptr(sks_key->attributes, SKS_VALUE,
				&value, &value_size))
		TEE_Panic(0);

	if (get_attribute(sks_key->attributes, SKS_TYPE, &key_type, NULL))
		return SKS_ERROR;

	switch (key_type) {
	case SKS_KEY_AES:

		if (function == SKS_FUNCTION_ENCRYPT ||
		    function == SKS_FUNCTION_DECRYPT) {
			mode = (function == SKS_FUNCTION_DECRYPT) ?
					TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
			size = value_size * 8;

			switch (proc_params->id) {
			case SKS_PROC_AES_ECB_NOPAD:
				algo = TEE_ALG_AES_ECB_NOPAD;
				break;
			case SKS_PROC_AES_CBC_NOPAD:
				algo = TEE_ALG_AES_CBC_NOPAD;
				break;
			case SKS_PROC_AES_CTR:
				algo = TEE_ALG_AES_CTR;
				break;
			case SKS_PROC_AES_CTS:
				algo = TEE_ALG_AES_CTS;
				break;
			default:
				EMSG("Operation not supported for process %s",
					sks2str_proc(proc_params->id));
				return SKS_INVALID_TYPE;
			}
			break;
		}

		if (function == SKS_FUNCTION_SIGN ||
		    function == SKS_FUNCTION_VERIFY) {

			switch (proc_params->id) {
			case SKS_PROC_AES_CMAC:
			case SKS_PROC_AES_CMAC_GENERAL:
				algo = TEE_ALG_AES_CMAC;
				mode = TEE_MODE_MAC;
				size = value_size * 8;
				break;

			case SKS_PROC_AES_CBC_MAC:
				algo = TEE_ALG_AES_CBC_MAC_NOPAD;
				mode = TEE_MODE_MAC;
				size = value_size * 8;
				break;

			default:
				EMSG("Operation not supported for process %s",
					sks2str_proc(proc_params->id));
				return SKS_INVALID_TYPE;
			}
			break;
		}

		EMSG("Operation not supported for object type %s",
			sks2str_key_type(key_type));
		return SKS_FAILED;

	case SKS_GENERIC_SECRET:
	case SKS_KEY_HMAC_MD5:
	case SKS_KEY_HMAC_SHA1:
	case SKS_KEY_HMAC_SHA224:
	case SKS_KEY_HMAC_SHA256:
	case SKS_KEY_HMAC_SHA384:
	case SKS_KEY_HMAC_SHA512:
		if (function == SKS_FUNCTION_SIGN ||
		    function == SKS_FUNCTION_VERIFY) {

			mode = TEE_MODE_MAC;
			size = value_size * 8;

			switch (proc_params->id) {
			case SKS_PROC_HMAC_MD5:
				algo = TEE_ALG_HMAC_MD5;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_MD5)
					return SKS_INVALID_TYPE;
				break;
			case SKS_PROC_HMAC_SHA1:
				algo = TEE_ALG_HMAC_SHA1;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_SHA1)
					return SKS_INVALID_TYPE;
				break;
			case SKS_PROC_HMAC_SHA224:
				algo = TEE_ALG_HMAC_SHA224;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_SHA224)
					return SKS_INVALID_TYPE;
				break;
			case SKS_PROC_HMAC_SHA256:
				algo = TEE_ALG_HMAC_SHA256;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_SHA256)
					return SKS_INVALID_TYPE;
				break;
			case SKS_PROC_HMAC_SHA384:
				algo = TEE_ALG_HMAC_SHA384;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_SHA384)
					return SKS_INVALID_TYPE;
				break;
			case SKS_PROC_HMAC_SHA512:
				algo = TEE_ALG_HMAC_SHA512;
				if (key_type != SKS_GENERIC_SECRET &&
				   key_type != SKS_KEY_HMAC_SHA512)
					return SKS_INVALID_TYPE;
				break;
			default:
				EMSG("Operation not supported for process %s",
					sks2str_proc(proc_params->id));
				return SKS_INVALID_TYPE;
			}
			break;
		}

		EMSG("Operation not supported for object type %s",
			sks2str_key_type(key_type));
		return SKS_FAILED;

	default:
		EMSG("Operation not supported for object type %s",
			sks2str_key_type(key_type));
		return SKS_FAILED;
	}

	if (session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_Panic(0);

	res = TEE_AllocateOperation(&session->tee_op_handle, algo, mode, size);
	if (res) {
		EMSG("Failed to allocate operation");
		return tee2sks_error(res);
	}

	return SKS_OK;
}

/* Convert SKS_KEY_xxx into GPD TEE_ATTR_xxx */
static uint32_t get_tee_object_info(uint32_t *type, uint32_t *attr,
				    struct sks_attrs_head *head)
{
	//
	// TODO: SKS_GENERIC_SECRET should be allowed to be used for HMAC_SHAx
	//
	switch (get_type(head)) {
	case SKS_KEY_AES:
		*type = TEE_TYPE_AES;
		goto secret;
	case SKS_GENERIC_SECRET:
		*type = TEE_TYPE_GENERIC_SECRET;
		goto secret;
	case SKS_KEY_HMAC_MD5:
		*type = TEE_TYPE_HMAC_MD5;
		goto secret;
	case SKS_KEY_HMAC_SHA1:
		*type = TEE_TYPE_HMAC_SHA1;
		goto secret;
	case SKS_KEY_HMAC_SHA224:
		*type = TEE_TYPE_HMAC_SHA224;
		goto secret;
	case SKS_KEY_HMAC_SHA256:
		*type = TEE_TYPE_HMAC_SHA256;
		goto secret;
	case SKS_KEY_HMAC_SHA384:
		*type = TEE_TYPE_HMAC_SHA384;
		goto secret;
	case SKS_KEY_HMAC_SHA512:
		*type = TEE_TYPE_HMAC_SHA512;
		goto secret;
	default:
		EMSG("Operation not supported for object type %s",
			sks2str_key_type(get_type(head)));
		return SKS_INVALID_TYPE;
	}

secret:
	*attr = TEE_ATTR_SECRET_VALUE;
	return SKS_OK;
}

static uint32_t load_key(struct sks_object *obj)
{
	uint32_t tee_obj_type;
	uint32_t tee_obj_attr;
	TEE_Attribute tee_key_attr;
	void *value;
	uint32_t value_size;
	uint32_t rv;
	TEE_Result res;

	/* Key already loaded, we have a handle */
	if (obj->key_handle != TEE_HANDLE_NULL)
		return SKS_OK;

	rv = get_tee_object_info(&tee_obj_type, &tee_obj_attr,
				 obj->attributes);
	if (rv) {
		EMSG("get_tee_object_info failed, %s", sks2str_rc(rv));
		return rv;
	}

	if (get_attribute_ptr(obj->attributes, SKS_VALUE, &value, &value_size))
		TEE_Panic(0);

	res = TEE_AllocateTransientObject(tee_obj_type, value_size * 8,
					  &obj->key_handle);
	if (res) {
		EMSG("TEE_AllocateTransientObject failed, %" PRIx32, res);
		return rv;;
	}

	TEE_InitRefAttribute(&tee_key_attr, tee_obj_attr, value, value_size);

	res = TEE_PopulateTransientObject(obj->key_handle, &tee_key_attr, 1);
	if (res) {
		EMSG("TEE_PopulateTransientObject failed, %" PRIx32, res);
		TEE_FreeTransientObject(obj->key_handle);
		obj->key_handle = TEE_HANDLE_NULL;
		return tee2sks_error(res);
	}

	return rv;
}

/*
 * ctrl = [session-handle][key-handle][mechanism-parameters]
 * in = none
 * out = none
 */
uint32_t entry_cipher_init(int teesess, TEE_Param *ctrl,
			   TEE_Param *in, TEE_Param *out, int decrypt)
{
	uint32_t rv;
	TEE_Result res;
	uint32_t ck_session;
	uint32_t key_handle;
	struct sks_object *obj;
	struct sks_reference *proc_params = NULL;
	struct pkcs11_session *pkcs_session = NULL;
	struct serialargs ctrlargs;
	void *init_params;
	size_t init_size;


	/*
	 * Arguments: ctrl=[32b-session-hld][32b-key-hdl][proc-parameters]
	 */
	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &ck_session, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_next(&ctrlargs, &key_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_sks_reference(&ctrlargs, &proc_params))
		return SKS_BAD_PARAM;

	/*
	 * Check PKCS session (arguments and session state)
	 */
	pkcs_session = get_pkcs_session(ck_session);
	if (!pkcs_session || pkcs_session->tee_session != teesess) {
		rv = SKS_INVALID_SESSION;
		goto error;
	}

	if (check_pkcs_session_processing_state(pkcs_session,
						PKCS11_SESSION_READY)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto error;
	}

	if (set_pkcs_session_processing_state(pkcs_session, decrypt ?
					      PKCS11_SESSION_DECRYPTING :
					      PKCS11_SESSION_ENCRYPTING)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto error;
	}

	/*
	 * Check parent key handle
	 */
	obj = object_get_tee_handle(key_handle, pkcs_session);
	if (!obj) {
		DMSG("Invalid key handle");
		rv = SKS_INVALID_KEY;
		goto error;
	}

	/*
	 * Check processing against parent key and token state
	 */
	rv = check_parent_attrs_against_processing(proc_params->id, decrypt ?
						   SKS_FUNCTION_DECRYPT :
						   SKS_FUNCTION_ENCRYPT,
						   obj->attributes);
	if (rv)
		goto error;

	rv = check_parent_attrs_against_token(pkcs_session, obj->attributes);
	if (rv)
		goto error;

	/*
	 * Allocate a TEE operation for the target processing and
	 * fill it with the expected operation parameters.
	 */
	rv = tee_operarion_params(pkcs_session, proc_params, obj, decrypt ?
				  SKS_FUNCTION_DECRYPT : SKS_FUNCTION_ENCRYPT);
	if (rv)
		goto error;


	/*
	 * Create a TEE object from the target key, if not yet done
	 */
	switch (get_class(obj->attributes)) {
	case SKS_OBJ_SYM_KEY:
		rv = load_key(obj);
		if (rv)
			goto error;

		break;

	default:
		rv = SKS_FAILED;		// FIXME: errno
		goto error;
	}

	res = TEE_SetOperationKey(pkcs_session->tee_op_handle, obj->key_handle);
	if (res) {
		EMSG("TEE_SetOperationKey failed %x", res);
		rv = tee2sks_error(res);
		goto error;
	}

	/*
	 * Specifc cipher initialization if any
	 */
	switch (proc_params->id) {
	case SKS_PROC_AES_ECB_NOPAD:
		if (proc_params->size) {
			DMSG("Bad params for %s", sks2str_proc(proc_params->id));
			rv = SKS_INVALID_PROC_PARAM;
			goto error;
		}

		init_params = NULL;
		init_size = 0;
		break;

	case SKS_PROC_AES_CBC_NOPAD:
	case SKS_PROC_AES_CBC_PAD:
	case SKS_PROC_AES_CTS:
		if (proc_params->size != 16) {
			DMSG("Expects 16 byte IV, not %d", proc_params->size);
			rv = SKS_INVALID_PROC_PARAM;
			goto error;
		}

		init_params = (void *)proc_params->data;
		init_size = 16;
		break;

	case SKS_PROC_AES_CTR:
	{
		struct sks_aes_ctr_params {
			uint32_t incr_counter;
			char counter_bits[16];
		} *params = (void *)proc_params->data;

		if (!ALIGNMENT_IS_OK(params, struct sks_aes_ctr_params)) {
			DMSG("Bad alignment of params");
			rv = SKS_INVALID_PROC_PARAM;
			goto error;
		}
		if (proc_params->size != sizeof(struct sks_aes_ctr_params)) {
			DMSG("Invalid AES CTR params: %d", proc_params->size);
			rv = SKS_INVALID_PROC_PARAM;
			goto error;
		}
		if (params->incr_counter != 1) {
			DMSG("Supports only 1 bit increment counter: %d",
							params->incr_counter);
			rv = SKS_INVALID_PROC_PARAM;
			goto error;
		}

		init_params = (void *)&params->counter_bits;
		init_size = 16;
		break;
	}
	default:
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
	}

	TEE_CipherInit(pkcs_session->tee_op_handle, init_params, init_size);

	pkcs_session->proc_id = proc_params->id;

	TEE_Free(proc_params);

	return SKS_OK;

error:
	if (set_pkcs_session_processing_state(pkcs_session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	if (pkcs_session->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(pkcs_session->tee_op_handle);
		pkcs_session->tee_op_handle = TEE_HANDLE_NULL;
	}

	TEE_Free(proc_params);

	return rv;
}

/*
 * ctrl = [session-handle]
 * in = data buffer
 * out = data buffer
 */
uint32_t entry_cipher_update(int teesess, TEE_Param *ctrl,
			     TEE_Param *in, TEE_Param *out, int decrypt)
{
	struct serialargs ctrlargs;
	TEE_Result res;
	uint32_t ck_session;
	struct pkcs11_session *pkcs_session;
	size_t in_size = in ? in->memref.size : 0;
	size_t out_size = out ? out->memref.size : 0;

	if (!ctrl)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &ck_session, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	pkcs_session = get_pkcs_session(ck_session);
	if (!pkcs_session || pkcs_session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	if (check_pkcs_session_processing_state(pkcs_session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return SKS_PROCESSING_INACTIVE;

	res = TEE_CipherUpdate(pkcs_session->tee_op_handle,
				in ? in->memref.buffer : NULL, in_size,
				out ? out->memref.buffer : NULL, &out_size);

	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
		if (set_pkcs_session_processing_state(pkcs_session,
						      PKCS11_SESSION_READY))
			TEE_Panic(0);

		TEE_FreeOperation(pkcs_session->tee_op_handle);
		pkcs_session->tee_op_handle = TEE_HANDLE_NULL;
		pkcs_session->proc_id = SKS_UNDEFINED_ID;
	} else {
		if (out)
			out->memref.size = out_size;
	}

	return tee2sks_error(res);
}

/*
 * ctrl = [session-handle]
 * in = none
 * out = data buffer
 */
uint32_t entry_cipher_final(int teesess, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out, int decrypt)
{
	TEE_Result res;
	struct serialargs ctrlargs;
	uint32_t ck_session;
	struct pkcs11_session *pkcs_session;
	size_t in_size = in ? in->memref.size : 0;
	size_t out_size = out ? out->memref.size : 0;

	if (!ctrl)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &ck_session, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	pkcs_session = get_pkcs_session(ck_session);
	if (!pkcs_session || pkcs_session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	if (check_pkcs_session_processing_state(pkcs_session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return SKS_PROCESSING_INACTIVE;

	res = TEE_CipherDoFinal(pkcs_session->tee_op_handle,
				in ? in->memref.buffer : NULL, in_size,
				out ? out->memref.buffer : NULL, &out_size);


	if (out && (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER))
		out->memref.size = out_size;

	/* Only a short buffer error can leave the operation active */
	if (res == TEE_ERROR_SHORT_BUFFER)
		return SKS_SHORT_BUFFER;

	if (set_pkcs_session_processing_state(pkcs_session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	TEE_FreeOperation(pkcs_session->tee_op_handle);
	pkcs_session->tee_op_handle = TEE_HANDLE_NULL;
	pkcs_session->proc_id = SKS_UNDEFINED_ID;

	return tee2sks_error(res);
}

static uint32_t generate_random_key_value(struct sks_attrs_head **head)
{
	uint32_t rv;
	void *data;
	size_t data_size;
	uint32_t value_len;
	void *value;

	if (!*head)
		return SKS_INVALID_ATTRIBUTES;

	rv = get_attribute_ptr(*head, SKS_VALUE_LEN, &data, &data_size);
	if (rv || data_size != sizeof(uint32_t)) {
		DMSG("%s", rv ? "No attribute value_len found" :
			"Invalid size for attribute VALUE_LEN");
		return SKS_INVALID_VALUE;
	}

	TEE_MemMove(&value_len, data, data_size);
	value = TEE_Malloc(value_len, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!value)
		return SKS_MEMORY;

	TEE_GenerateRandom(value, value_len);

	rv = add_attribute(head, SKS_VALUE, value, value_len);
	if (rv)
		return rv;

	return rv;
}

uint32_t entry_generate_object(int teesess,
			       TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	uint32_t rv;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_reference *proc_params = NULL;
	struct sks_attrs_head *head = NULL;
	struct sks_object_head *template = NULL;
	size_t template_size;
	uint32_t obj_handle;

	/*
	 * Collect the arguments
	 */

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(uint32_t))
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &session_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_sks_reference(&ctrlargs, &proc_params))
		return SKS_BAD_PARAM;

	if (serialargs_get_sks_attributes(&ctrlargs, &template))
		return SKS_BAD_PARAM;

	template_size = sizeof(*template) + template->blobs_size;

	/*
	 * Check arguments
	 */

	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess) {
		rv = SKS_INVALID_SESSION;
		goto bail;
	}

	if (check_pkcs_session_processing_state(session,
						PKCS11_SESSION_READY)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto bail;
	}

	/*
	 * Prepare a clean initial state for the requested object attributes.
	 * Free temorary template once done.
	 */
	rv = create_attributes_from_template(&head, template, template_size,
					     SKS_FUNCTION_GENERATE);
	TEE_Free(template);
	template = NULL;
	if (rv)
		goto bail;

	/*
	 * Check created object against processing and token state.
	 */
	rv = check_created_attrs_against_processing(proc_params->id, head);
	if (rv)
		goto bail;

	rv = check_created_attrs_against_token(session, head);
	if (rv)
		goto bail;

	/*
	 * Execute the target processing and add value as attribute SKS_VALUE.
	 * Symm key generation: depens on target processing to be used.
	 */
	switch (proc_params->id) {
	case SKS_PROC_GENERIC_GENERATE:
	case SKS_PROC_AES_GENERATE:
		/* Generate random of size specified by attribute VALUE_LEN */
		rv = generate_random_key_value(&head);
		if (rv)
			goto bail;
		break;

	default:
		rv = SKS_INVALID_PROC;
		goto bail;
	}

	TEE_Free(proc_params);
	proc_params = NULL;

	/*
	 * Object is ready, register it and return a handle.
	 */
	rv = create_object(session, head, &obj_handle);
	if (rv)
		goto bail;

	/*
	 * Now obj_handle (through the related struct sks_object instance)
	 * owns the serialized buffer that holds the object attributes.
	 * We reset attrs->buffer to NULL as serializer object is no more
	 * the attributes buffer owner.
	 */
	head = NULL;

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

bail:
	TEE_Free(proc_params);
	TEE_Free(template);
	TEE_Free(head);

	return rv;
}

/*
 * ctrl = [session-handle][key-handle][mechanism-parameters]
 * in = none
 * out = none
 */
uint32_t entry_signverify_init(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int sign)
{
	uint32_t rv;
	TEE_Result res;
	struct serialargs ctrlargs;
	uint32_t session_handle;
	struct pkcs11_session *session;
	struct sks_reference *proc_params = NULL;
	uint32_t key_handle;
	struct sks_object *obj;

	/*
	 * Collect the arguments
	 */

	if (!ctrl || in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &session_handle, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	if (serialargs_get_next(&ctrlargs, &key_handle, sizeof(uint32_t))) {
		rv = SKS_BAD_PARAM;
		goto error;
	}

	if (serialargs_get_sks_reference(&ctrlargs, &proc_params)) {
		rv = SKS_BAD_PARAM;
		goto error;
	}

	/*
	 * Check arguments
	 */

	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess) {
		rv = SKS_INVALID_SESSION;
		goto error;
	}

	if (check_pkcs_session_processing_state(session,
						PKCS11_SESSION_READY)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto error;
	}

	if (set_pkcs_session_processing_state(session, sign ?
					      PKCS11_SESSION_SIGNING :
					      PKCS11_SESSION_VERIFYING)) {
		rv = SKS_PROCESSING_ACTIVE;
		goto error;
	}

	obj = object_get_tee_handle(key_handle, session);
	if (!obj) {
		DMSG("Invalid key handle");
		rv = SKS_INVALID_KEY;
		goto error;
	}

	/*
	 * Check created object against processing and token state.
	 */
	rv = check_parent_attrs_against_processing(proc_params->id, sign ?
						   SKS_FUNCTION_SIGN :
						   SKS_FUNCTION_VERIFY,
						   obj->attributes);
	if (rv)
		goto error;

	rv = check_parent_attrs_against_token(session, obj->attributes);
	if (rv)
		goto error;

	/*
	 * Allocate a TEE operation for the target processing and
	 * fill it with the expected operation parameters.
	 */
	rv = tee_operarion_params(session, proc_params, obj, sign ?
				  SKS_FUNCTION_SIGN : SKS_FUNCTION_VERIFY);
	if (rv)
		goto error;

	/*
	 * Execute the target processing and add value as attribute SKS_VALUE.
	 * Symm key generation: depens on target processing to be used.
	 */
	switch (proc_params->id) {
	case SKS_PROC_AES_CMAC:
	case SKS_PROC_AES_CMAC_GENERAL:
	case SKS_PROC_HMAC_MD5:
	case SKS_PROC_HMAC_SHA1:
	case SKS_PROC_HMAC_SHA224:
	case SKS_PROC_HMAC_SHA256:
	case SKS_PROC_HMAC_SHA384:
	case SKS_PROC_HMAC_SHA512:
	case SKS_PROC_AES_CBC_MAC:
		rv = load_key(obj);
		if (rv)
			goto error;

		break;

	default:
		rv = SKS_INVALID_PROC;
		goto error;
	}

	res = TEE_SetOperationKey(session->tee_op_handle, obj->key_handle);
	if (res) {
		EMSG("TEE_SetOperationKey failed %x", res);
		rv = tee2sks_error(res);
		goto error;
	}

	/*
	 * Specifc cipher initialization if any
	 */
	switch (proc_params->id) {
	case SKS_PROC_AES_CMAC_GENERAL:
	case SKS_PROC_AES_CMAC:
	case SKS_PROC_HMAC_MD5:
	case SKS_PROC_HMAC_SHA1:
	case SKS_PROC_HMAC_SHA224:
	case SKS_PROC_HMAC_SHA256:
	case SKS_PROC_HMAC_SHA384:
	case SKS_PROC_HMAC_SHA512:
	case SKS_PROC_AES_CBC_MAC:
		// TODO: get the desired output size
		TEE_MACInit(session->tee_op_handle, NULL, 0);
		break;

	default:
		TEE_Panic(TEE_ERROR_NOT_IMPLEMENTED);
	}

	session->proc_id = proc_params->id;

	TEE_Free(proc_params);

	return SKS_OK;

error:
	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	if (session->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(session->tee_op_handle);
		session->tee_op_handle = TEE_HANDLE_NULL;
	}

	TEE_Free(proc_params);

	return rv;
}

/*
 * ctrl = [session-handle]
 * in = input data
 * out = none
 */
uint32_t entry_signverify_update(int teesess, TEE_Param *ctrl,
				 TEE_Param *in, TEE_Param *out, int sign)
{
	struct serialargs ctrlargs;
	uint32_t ck_session;
	struct pkcs11_session *session;

	if (!ctrl || !in || out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &ck_session, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	session = get_pkcs_session(ck_session);
	if (!session || session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	if (check_pkcs_session_processing_state(session, sign ?
						PKCS11_SESSION_SIGNING :
						PKCS11_SESSION_VERIFYING))
		return SKS_PROCESSING_INACTIVE;

	switch (session->proc_id) {
	case SKS_PROC_AES_CMAC_GENERAL:
	case SKS_PROC_AES_CMAC:
	case SKS_PROC_HMAC_MD5:
	case SKS_PROC_HMAC_SHA1:
	case SKS_PROC_HMAC_SHA224:
	case SKS_PROC_HMAC_SHA256:
	case SKS_PROC_HMAC_SHA384:
	case SKS_PROC_HMAC_SHA512:
	case SKS_PROC_AES_CBC_MAC:
		TEE_MACUpdate(session->tee_op_handle,
				in->memref.buffer, in->memref.size);
		break;

	default:
		TEE_Panic(0);
	}

	return SKS_OK;
}

/*
 * ctrl = [session-handle]
 * in = none
 * out = data buffer
 */
uint32_t entry_signverify_final(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int sign)
{
	TEE_Result res;
	struct serialargs ctrlargs;
	uint32_t ck_session;
	struct pkcs11_session *session;
	uint32_t out_size = out->memref.size;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	if (serialargs_get_next(&ctrlargs, &ck_session, sizeof(uint32_t)))
		return SKS_BAD_PARAM;

	session = get_pkcs_session(ck_session);
	if (!session || session->tee_session != teesess)
		return SKS_INVALID_SESSION;

	if (check_pkcs_session_processing_state(session, sign ?
						PKCS11_SESSION_SIGNING :
						PKCS11_SESSION_VERIFYING))
		return SKS_PROCESSING_INACTIVE;

	switch (session->proc_id) {
	case SKS_PROC_AES_CMAC_GENERAL:
	case SKS_PROC_AES_CMAC:
	case SKS_PROC_HMAC_MD5:
	case SKS_PROC_HMAC_SHA1:
	case SKS_PROC_HMAC_SHA224:
	case SKS_PROC_HMAC_SHA256:
	case SKS_PROC_HMAC_SHA384:
	case SKS_PROC_HMAC_SHA512:
	case SKS_PROC_AES_CBC_MAC:
		if (sign)
			res = TEE_MACComputeFinal(session->tee_op_handle,
						  NULL, 0, out->memref.buffer,
						  &out_size);
		else
			res = TEE_MACCompareFinal(session->tee_op_handle,
						  NULL, 0, out->memref.buffer,
						  out_size);
		break;
	default:
		TEE_Panic(0);
	}

	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER)
		out->memref.size = out_size;

	/* Only a short buffer error can leave the operation active */
	if (res == TEE_ERROR_SHORT_BUFFER)
		return SKS_SHORT_BUFFER;

	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	TEE_FreeOperation(session->tee_op_handle);
	session->tee_op_handle = TEE_HANDLE_NULL;
	session->proc_id = SKS_UNDEFINED_ID;

	return tee2sks_error(res);
}
