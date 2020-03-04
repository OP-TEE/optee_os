// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_internal_api.h>
#include <trace.h>

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

uint32_t serialargs_get(struct serialargs *args, void *out, size_t size)
{
	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	TEE_MemMove(out, args->next, size);

	args->next += size;

	return PKCS11_CKR_OK;
}

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size)
{
	void *ptr = NULL;

	if (!size) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	ptr = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!ptr)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_MemMove(ptr, args->next, size);

	args->next += size;
	*out = ptr;

	return PKCS11_CKR_OK;
}

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size)
{
	void *ptr = args->next;

	if (!size) {
		*out = NULL;
		return PKCS11_CKR_OK;
	}

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return PKCS11_CKR_ARGUMENTS_BAD;
	}

	args->next += size;
	*out = ptr;

	return PKCS11_CKR_OK;
}

bool serialargs_remaining_bytes(struct serialargs *args)
{
	return args->next < args->start + args->size;
}
