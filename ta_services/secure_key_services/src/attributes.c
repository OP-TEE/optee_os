/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <sks_internal_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <util.h>

#include "attributes.h"
#include "sks_helpers.h"
#include "serializer.h"

uint32_t init_attributes_head(struct sks_attrs_head **head)
{
	*head = TEE_Malloc(sizeof(struct sks_attrs_head), 0);
	if (!*head)
		return SKS_MEMORY;

	(*head)->blobs_size = 0;
	(*head)->blobs_count = 0;
#ifdef SKS_SHEAD_WITH_TYPE
	(*head)->class = SKS_UNDEFINED_ID;
	(*head)->type = SKS_UNDEFINED_ID;
#endif
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	(*head)->boolpropl = 0;
	(*head)->boolproph = 0;
#endif

	return SKS_OK;
}

static bool attribute_is_in_head(uint32_t attribute __maybe_unused)
{
#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CLASS || sks_attr_is_type(attribute))
		return true;
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	if (sks_attr2boolprop_shift(attribute) >= 0)
		return true;
#endif

	return false;
}

uint32_t add_attribute(struct sks_attrs_head **head,
			uint32_t attribute, void *data, size_t size)
{
	size_t buf_len = sizeof(struct sks_attrs_head) + (*head)->blobs_size;
	uint32_t rv;
	uint32_t data32;
	char **bstart = (void *)head;
	int shift __maybe_unused;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CLASS || sks_attr_is_type(attribute)) {
		assert(size == sizeof(uint32_t));

		TEE_MemMove(attribute == SKS_CLASS ?
				&(*head)->class : &(*head)->type,
				data, sizeof(uint32_t));

		return SKS_OK;
	}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(attribute);
	if (shift >= 0) {
		uint32_t mask = shift < 32 ? BIT(shift) : BIT(shift - 32);
		uint32_t val = *(uint8_t *)data ? mask : 0;

		if (size != sizeof(uint8_t))
			return SKS_INVALID_ATTRIBUTES;

		if (shift < 32)
			(*head)->boolpropl = ((*head)->boolpropl & ~mask) | val;
		else
			(*head)->boolproph = ((*head)->boolproph & ~mask) | val;

		return SKS_OK;
	}
#endif

	data32 = attribute;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	data32 = size;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialize(bstart, &buf_len, data, size);
	if (rv)
		return rv;

	/* Alloced buffer is always 64byte align, safe for us */
	head = (void *)bstart;
	(*head)->blobs_size += 2 * sizeof(uint32_t) + size;
	(*head)->blobs_count++;

	return rv;
}

uint32_t remove_attribute(struct sks_attrs_head **head, uint32_t attribute)
{
	struct sks_attrs_head *h = *head;
	char *cur;
	char *end;
	size_t next_off;

	/* Can't remove an attribute that is defined in the head */
	if (attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute in the head");
		return SKS_FAILED;
	}

	/* Let's find the target attribute */
	cur = (char *)h + sizeof(struct sks_attrs_head);
	end = cur + h->blobs_size;
	for (; cur < end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->blobs_count--;
		h->blobs_size -= next_off;
		end -= next_off;
		next_off = 0;
		return SKS_OK;
	}

	DMSG("SKS_VALUE not found");
	return SKS_NOT_FOUND;
}

uint32_t remove_attribute_check(struct sks_attrs_head **head, uint32_t attribute,
				size_t max_check)
{
	struct sks_attrs_head *h = *head;
	char *cur;
	char *end;
	size_t next_off;
	size_t found = 0;

		/* Can't remove an attribute that is defined in the head */
	if (attribute_is_in_head(attribute)) {
		EMSG("Can't remove attribute is in the head");
		return SKS_FAILED;
	}

	/* Let's find the target attribute */
	//cur = (char *)h->blobs;
	cur = (char *)h + sizeof(struct sks_attrs_head);
	end = cur + h->blobs_size;
	for (; cur < end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		found++;
		if (found > max_check) {
			DMSG("Too many attribute occurences");
			return SKS_FAILED;
		}

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		h->blobs_count--;
		h->blobs_size -= next_off;
		end -= next_off;
		next_off = 0;
	}

	/* sanity */
	if (cur != end) {
		EMSG("Bad end address");
		return SKS_ERROR;
	}

	if (!found) {
		EMSG("SKS_VALUE not found");
		return SKS_FAILED;

	}

	return SKS_OK;
}

void get_attribute_ptrs(struct sks_attrs_head *head, uint32_t attribute,
			void **attr, size_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct sks_attrs_head);
	char *end = cur + head->blobs_size;
	size_t next_off;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	size_t *attr_size_ptr = attr_size;

	for (; cur < end; cur += next_off) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr)
			*attr_ptr++ = cur + sizeof(sks_ref);

		if (attr_size)
			*attr_size_ptr++ = sks_ref.size;

		if (found == max_found)
			break;
	}

	/* Sanity */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}

	*count = found;
}

uint32_t get_attribute_ptr(struct sks_attrs_head *head, uint32_t attribute,
			   void **attr_ptr, size_t *attr_size)
{
	size_t count = 1;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CLASS) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->class;

		return SKS_OK;
	}
	if (attribute == SKS_TYPE) {
		if (attr_size)
			*attr_size = sizeof(uint32_t);
		if (attr_ptr)
			*attr_ptr = &head->type;

		return SKS_OK;
	}
#endif
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	if (sks_attr2boolprop_shift(attribute) >= 0)
		TEE_Panic(0);
#endif

	get_attribute_ptrs(head, attribute, attr_ptr, attr_size, &count);

	if (count != 1)
		return SKS_ERROR;

	return SKS_OK;
}

uint32_t get_attribute(struct sks_attrs_head *head, uint32_t attribute,
			void *attr, size_t *attr_size)
{
	uint32_t rc;
	void *attr_ptr;
	size_t size;
	uint8_t bbool __maybe_unused;
	int shift __maybe_unused;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CLASS) {
		size = sizeof(uint32_t);
		attr_ptr = &head->class;
		goto found;
	}

	if (attribute == SKS_TYPE) {
		size = sizeof(uint32_t);
		attr_ptr = &head->type;
		goto found;
	}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(attribute);
	if (shift >= 0) {
		uint32_t *boolprop;

		boolprop = (shift < 32) ? &head->boolpropl : &head->boolproph;
		bbool = (*boolprop & (1 << (shift % 32))) ? SKS_TRUE : SKS_FALSE;

		size = sizeof(uint8_t);
		attr_ptr = &bbool;
		goto found;
	}
#endif
	rc = get_attribute_ptr(head, attribute, &attr_ptr, &size);
	if (rc == SKS_OK)
		goto found;

	return rc;

found:
	if (attr_size && *attr_size != size) {
		*attr_size = size;
		/* This reuses buffer-to-small for any bad size matching */
		return SKS_SHORT_BUFFER;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return SKS_OK;
}

/*
 * Debug: dump CK attribute array to output trace
 */

static uint32_t __trace_attributes(char *prefix, void *src, void *end)
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
		switch (sks_ref.size) {
		case 0:
			IMSG_RAW("%s attr %s (0x%" PRIx32
				 " %" PRIu32 " byte) :",
				 prefix, sks2str_attr(sks_ref.id),
				 sks_ref.id, sks_ref.size);
			break;
		case 1:
			IMSG_RAW("%s attr %s (0x%" PRIx32
				 " %" PRIu32 " byte) : %02x ",
				 prefix, sks2str_attr(sks_ref.id),
				 sks_ref.id, sks_ref.size,
				 *((char *)cur + sizeof(sks_ref) + 0));
			break;
		case 2:
			IMSG_RAW("%s attr %s (0x%" PRIx32
				 " %" PRIu32 " byte) : %02x %02x",
				 prefix, sks2str_attr(sks_ref.id),
				 sks_ref.id, sks_ref.size,
				 *((char *)cur + sizeof(sks_ref) + 0),
				 *((char *)cur + sizeof(sks_ref) + 1));
			break;
		case 3:
			IMSG_RAW("%s attr %s (0x%" PRIx32
				 " %" PRIu32 " byte) : %02x %02x %02x",
				 prefix, sks2str_attr(sks_ref.id),
				 sks_ref.id, sks_ref.size,
				 *((char *)cur + sizeof(sks_ref) + 0),
				 *((char *)cur + sizeof(sks_ref) + 1),
				 *((char *)cur + sizeof(sks_ref) + 2));
			break;
		default:
			IMSG_RAW("%s attr %s (0x%" PRIx32
				 " %" PRIu32 " byte) : %02x %02x %02x %02x",
				 prefix, sks2str_attr(sks_ref.id),
				 sks_ref.id, sks_ref.size,
				 *((char *)cur + sizeof(sks_ref) + 0),
				 *((char *)cur + sizeof(sks_ref) + 1),
				 *((char *)cur + sizeof(sks_ref) + 2),
				 *((char *)cur + sizeof(sks_ref) + 3));
			break;
		}

		switch (sks_ref.id) {
		case SKS_WRAP_ATTRIBS:
		case SKS_UNWRAP_ATTRIBS:
		case SKS_DERIVE_ATTRIBS:
			trace_attributes(prefix2,
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

uint32_t trace_attributes(const char *prefix, void *ref)
{
	struct sks_attrs_head head;
	char *pre;
	uint32_t rc;
	size_t n __maybe_unused;

	TEE_MemMove(&head, ref, sizeof(head));

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return SKS_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	// TODO: nice ui to trace the attribute info
	IMSG_RAW("%s,--- (serial object) Attributes list --------\n", pre);
	IMSG_RAW("%s| %" PRIu32 " item(s) - %" PRIu32 " bytes\n",
		pre, head.blobs_count, head.blobs_size);
#ifdef SKS_SHEAD_WITH_TYPE
	IMSG_RAW("%s| class (0x%" PRIx32 ") %s type (0x%" PRIx32 ") %s\n",
		 pre, head.class, sks2str_class(head.class),
		 head.type, sks2str_type(head.type, head.class));
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	for (n = 0; n < SKS_BOOLPROP_LAST_SHIFT; n++)
		IMSG_RAW("%s| attr %s (0x%" PRIx32 " %" PRIu32 " byte) : %u\n",
			 prefix, sks2str_attr(SKS_BP_ATTR(n)), SKS_BP_ATTR(n), 1,
			 n < 32 ?
			 !!(head.boolpropl & BIT(n)) :
			 !!(head.boolproph & BIT(n - 32)));
#endif

	pre[prefix ? strlen(prefix) : 0] = '|';
	rc = __trace_attributes(pre, (char *)ref + sizeof(head),
			        (char *)ref + sizeof(head) + head.blobs_size);
	if (rc)
		goto bail;

	IMSG_RAW("%s`-----------------------\n", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rc;
}
