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
 * Debug: dump CK attribute array to output trace
 */

static uint32_t trace_attributes(char *prefix, void *src, void *end)
{
	size_t next_off = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return SKS_MEMORY;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		// TODO: nice ui to trace the attribute info
		IMSG("%s attr %s (%" PRIx32 " %" PRIx32 " byte) : %02x %02x %02x %02x ...\n",
			prefix, sks2str_attr(sks_ref.id), sks_ref.id, sks_ref.size,
			*((char *)cur + sizeof(sks_ref) + 0),
			*((char *)cur + sizeof(sks_ref) + 1),
			*((char *)cur + sizeof(sks_ref) + 2),
			*((char *)cur + sizeof(sks_ref) + 3));

		switch (sks_ref.id) {
		case SKS_WRAP_ATTRIBS:
		case SKS_UNWRAP_ATTRIBS:
		case SKS_DERIVE_ATTRIBS:
			trace_attributes_from_sobj_head(prefix2,
						(void *)(cur + sizeof(sks_ref)));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		EMSG("unexpected none alignement\n");
	}

	TEE_Free(prefix2);
	return SKS_OK;
}

uint32_t trace_attributes_from_sobj_head(const char *prefix, void *ref)
{
	struct sks_sobj_head head;
	char *pre;
	uint32_t rc;

	TEE_MemMove(&head, ref, sizeof(head));

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return SKS_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	// TODO: nice ui to trace the attribute info
	IMSG_RAW("%s,--- (serial object) Attributes list --------\n", pre);
	IMSG_RAW("%s| %" PRIx32 " item(s) - %" PRIu32 " bytes\n",
		pre, head.blobs_count, head.blobs_size);
#ifdef SKS_SHEAD_WITH_TYPE
	IMSG_RAW("%s| class (%" PRIx32 ") %s type (%" PRIx32 ") %s"
		 " - boolpropl/h 0x%" PRIx32 "/0x%" PRIx32 "\n",
		 pre, head.object, sks2str_class(head.object),
		 head.type, sks2str_type(head.type, head.object),
#ifdef SKS_SHEAD_WITH_BOOLPROPS
		 head.boolpropl, head.boolproph
#else
		 ~0, ~0
#endif
		 );
#endif

	pre[prefix ? strlen(prefix) : 0] = '|';
	rc = trace_attributes(pre, (char *)ref + sizeof(head),
			      (char *)ref + sizeof(head) + head.blobs_size);
	if (rc)
		goto bail;

	IMSG_RAW("%s`-----------------------\n", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rc;
}
