/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_internal_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "serializer.h"
#include "sks_helpers.h"

/*
 * Util routines for serializes unformatted arguments in a client memref
 */
void serialargs_init(struct serialargs *args, void *in, size_t size)
{
	args->start = in;
	args->next = in;
	args->size = size;
}

int serialargs_get_next(struct serialargs *args, void *out, size_t size)
{
	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return 1;
	}

	TEE_MemMove(out, args->next, size);

	args->next += size;

	return 0;
}

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size)
{
	void *ptr;

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return SKS_BAD_PARAM;
	}

	ptr = TEE_Malloc(size, 0);
	if (!ptr)
		return SKS_MEMORY;

	TEE_MemMove(ptr, args->next, size);

	args->next += size;
	*out = ptr;

	return SKS_OK;
}

void *serialargs_get_next_ptr(struct serialargs *args, size_t size)
{
	void *ptr = args->next;

	if (args->next + size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start), size);
		return NULL;
	}

	args->next += size;

	return ptr;
}

size_t serialargs_remaining_size(struct serialargs *args)
{
	return args->start + args->size - args->next;
}

int serialargs_get_sks_reference(struct serialargs *args,
				 struct sks_reference **out)
{
	struct sks_reference head;
	size_t out_size = sizeof(head);
	void *pref;

	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return 1;
	}

	TEE_MemMove(&head, args->next, out_size);

	out_size += head.size;
	if (args->next + out_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     out_size);
		return 1;
	}

	pref = TEE_Malloc(out_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pref)
		return 1;

	TEE_MemMove(pref, args->next, out_size);
	args->next += out_size;

	*out = pref;

	return 0;
}

int serialargs_get_sks_attributes(struct serialargs *args,
				  struct sks_object_head **out)
{
	struct sks_object_head attr;
	struct sks_object_head *pattr;
	size_t attr_size = sizeof(attr);

	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect at least %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return 1;
	}

	TEE_MemMove(&attr, args->next, attr_size);

	attr_size += attr.blobs_size;
	if (args->next + attr_size > args->start + args->size) {
		EMSG("arg too short: full %zd, remain %zd, expect %zd",
		     args->size, args->size - (args->next - args->start),
		     attr_size);
		return 1;
	}

	pattr = TEE_Malloc(attr_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!pattr)
		return 1;

	TEE_MemMove(pattr, args->next, attr_size);
	args->next += attr_size;

	*out = pattr;

	return 0;
}

/*
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignement of appended data in the buffer.
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf;
	size_t nlen = *blen + len;

	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return SKS_MEMORY;

	TEE_MemMove(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return SKS_OK;
}
