// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <trace.h>
#include <util.h>

#include "pkcs11_token.h"
#include "serializer.h"

/*
 * Util routines for serializes unformatted arguments in a client memref
 */
void serialargs_init(struct serialargs *args, void *in, size_t size)
{
	args->start = in;
	args->next = in;
	args->size = size;
}

enum pkcs11_rc serialargs_get(struct serialargs *args, void *out, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	void *src = NULL;

	rc = serialargs_get_ptr(args, &src, size);
	if (!rc)
		TEE_MemMove(out, src, size);

	return rc;
}

static enum pkcs11_rc alloc_and_get(struct serialargs *args, char *orig_next,
				    const void *buf0, size_t buf0_sz,
				    void **out, size_t size)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t *ptr = NULL;
	void *src = NULL;
	size_t sz = 0;

	if (ADD_OVERFLOW(buf0_sz, size, &sz))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!sz) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	rc = serialargs_get_ptr(args, &src, size);
	if (rc)
		return rc;

	ptr = TEE_Malloc(sz, TEE_MALLOC_FILL_ZERO);
	if (!ptr) {
		args->next = orig_next;
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	TEE_MemMove(ptr, buf0, buf0_sz);
	TEE_MemMove(ptr + buf0_sz, src, size);

	*out = ptr;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc serialargs_alloc_and_get(struct serialargs *args,
					void **out, size_t size)
{
	return alloc_and_get(args, args->next, NULL, 0, out, size);
}

enum pkcs11_rc serialargs_get_ptr(struct serialargs *args, void **out,
				  size_t size)
{
	void *ptr = args->next;
	vaddr_t next_end = 0;

	if (ADD_OVERFLOW((vaddr_t)args->next, size, &next_end))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!size) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	if ((char *)next_end > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	args->next += size;
	*out = ptr;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc
serialargs_alloc_get_one_attribute(struct serialargs *args,
				   struct pkcs11_attribute_head **out)
{
	struct pkcs11_attribute_head head = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	char *orig_next = args->next;
	void *p = NULL;

	rc = serialargs_get(args, &head, sizeof(head));
	if (rc)
		return rc;

	rc = alloc_and_get(args, orig_next, &head, sizeof(head), &p, head.size);
	if (rc)
		return rc;

	*out = p;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc serialargs_alloc_get_attributes(struct serialargs *args,
					       struct pkcs11_object_head **out)
{
	struct pkcs11_object_head attr = { };
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	char *orig_next = args->next;
	void *p = NULL;

	rc = serialargs_get(args, &attr, sizeof(attr));
	if (rc)
		return rc;

	rc = alloc_and_get(args, orig_next, &attr, sizeof(attr), &p,
			   attr.attrs_size);
	if (rc)
		return rc;

	*out = p;

	return PKCS11_CKR_OK;
}

bool serialargs_remaining_bytes(struct serialargs *args)
{
	return args->next < args->start + args->size;
}

enum pkcs11_rc serialargs_get_session_from_handle(struct serialargs *args,
						  struct pkcs11_client *client,
						  struct pkcs11_session **sess)
{
	uint32_t rv = PKCS11_CKR_GENERAL_ERROR;
	uint32_t session_handle = 0;
	struct pkcs11_session *session = NULL;

	rv = serialargs_get(args, &session_handle, sizeof(uint32_t));
	if (rv)
		return rv;

	session = pkcs11_handle2session(session_handle, client);
	if (!session)
		return PKCS11_CKR_SESSION_HANDLE_INVALID;

	*sess = session;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf = NULL;
	size_t nlen = 0;

	if (ADD_OVERFLOW(*blen, len, &nlen))
		return PKCS11_CKR_ARGUMENTS_BAD;

	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_MemMove(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return PKCS11_CKR_OK;
}

