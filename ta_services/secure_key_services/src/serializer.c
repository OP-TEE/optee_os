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
 * Tools for manupilation of serialized attributes
 */
size_t serial_get_size(void *ref)
{
	struct sks_sobj_head head;

	TEE_MemMove(&head, ref, sizeof(head));

	return head.blobs_size + sizeof(head);
}

size_t serial_get_count(void *ref)
{
	struct sks_sobj_head head;

	TEE_MemMove(&head, ref, sizeof(head));

	return head.blobs_count;
}

void serial_get_attributes_ptr(struct sks_sobj_head *head, uint32_t attribute,
				void **attr, size_t *attr_size, size_t *count)
{
	char *cur = (char *)head + sizeof(struct sks_sobj_head);
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

uint32_t serial_get_attribute_ptr(struct sks_sobj_head *head, uint32_t attribute,
				void **attr_ptr, size_t *attr_size)
{
	size_t count = 1;

	serial_get_attributes_ptr(head, attribute, attr_ptr, attr_size, &count);

	if (count != 1)
		return SKS_ERROR;

	return SKS_OK;
}

uint32_t serial_get_attribute(struct sks_sobj_head *head, uint32_t attribute,
			      void *attr, size_t *attr_size)
{
	uint32_t rc;
	void *attr_ptr;
	size_t size;
	uint8_t bbool __maybe_unused;

#ifdef SKS_SHEAD_WITH_TYPE
	if (attribute == SKS_CLASS) {
		size = sizeof(uint32_t);
		attr_ptr = &head->object;
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

		boolprop = (shift > 31) ? head->boolpropl : head->boolproph;
		bbool = !!(*boolprop & (1 << shift));

		size = sizeof(uint8_t);
		attr_ptr = &bbool;
		goto found;
	}
#endif
	rc = serial_get_attribute_ptr(head, attribute, &attr_ptr, &size);
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

#ifdef SKS_SHEAD_WITH_TYPE
uint32_t serial_get_class(void *ref)
{
	struct sks_sobj_head head;

	TEE_MemMove(&head, ref, sizeof(head));

	return head.object;
}

uint32_t serial_get_type(void *ref)
{
	struct sks_sobj_head head;

	TEE_MemMove(&head, ref, sizeof(head));

	return head.type;
}
#else

uint32_t serial_get_class(void *ref)
{
	uint32_t class;
	size_t size = sizeof(class);

	if (serial_get_attribute(ref, SKS_CLASS, &class, &size))
		return SKS_UNDEFINED_ID;

	return class;
}

uint32_t serial_get_type(void *ref)
{
	uint32_t type;
	size_t size = sizeof(type);

	if (serial_get_attribute(ref, SKS_TYPE, &type, &size))
		return SKS_UNDEFINED_ID;

	return type;
}
#endif


/*
 * Removing an attribute from a serialized object
 */

static bool attribute_is_in_head(struct serializer *ref __maybe_unused,
				 uint32_t attribute __maybe_unused)
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

uint32_t serial_add_attribute(struct sks_sobj_head **head,
			      uint32_t attribute, void *data, size_t size)
{
	size_t buf_len = sizeof(struct sks_sobj_head) + (*head)->blobs_size;
	uint32_t rv;
	uint32_t data32;
	char **bstart = (void *)head;

	data32 = attribute;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	data32 = size;
	rv = serialize(bstart, &buf_len, &data32, sizeof(uint32_t));
	if (rv)
		return rv;

	rv = serialize(bstart, &buf_len, &data, size);
	if (rv)
		return rv;

	/* Alloced buffer is always 64byte align, safe for us */
	head = (void *)bstart;
	(*head)->blobs_size += 2 * sizeof(uint32_t) + size;
	(*head)->blobs_count++;

	return rv;
}

uint32_t serializer_add_attribute(struct serializer *obj,
				  uint32_t id, void *data, size_t size)
{
	int shift __maybe_unused;

#ifdef SKS_SHEAD_WITH_TYPE
	/* Case attribute in the header */
	if (id == SKS_CLASS) {
		if (size != sizeof(uint32_t))
			return SKS_ERROR;

		TEE_MemMove(&obj->class, data, sizeof(uint32_t));
		return SKS_OK;
	}

	if (id == SKS_TYPE) {
		if (size != sizeof(uint32_t))
			return SKS_ERROR;

		TEE_MemMove(&obj->type, data, sizeof(uint32_t));
		return SKS_OK;
	}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
	shift = sks_attr2boolprop_shift(id);
	if (shift >= 0) {
		uint32_t *bp;

		if (size != sizeof(uint8_t))
			return SKS_ERROR;

		bp = obj->boolprop + (shift / 32);
		if (*(uint8_t *)data)
			*bp |= 1 << (shift % 32);
		else
			*bp &= ~(1 << (shift % 32));

		return SKS_OK;
	}
#endif

	/*
	 * TODO: in case of attribute that should to defined once per object,
	 * we must check that the attribute is not already in the object
	 * attributes list
	 */

	/* Case attribute in the attributes list */
	return serialize_sks_ref(obj, id, data, size);
}

uint32_t serializer_remove_attribute(struct serializer *obj, uint32_t attribute)
{
	char *cur;
	char *end;
	size_t next_off;
	int found = 0;

	/* Can't remove an attribute that is defined in the head */
	if (attribute_is_in_head(obj, attribute)) {
		EMSG("Can't remove attribute is in the head");
		return SKS_FAILED;
	}

	/* Let's find the target attribute */
	cur = obj->buffer + sizeof_serial_object_head(obj);
	end = obj->buffer + obj->size;
	for (; cur < end; cur += next_off) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next_off = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		if (found) {
			EMSG("Attribute found twice");
			return SKS_FAILED;
		}
		found = 1;

		TEE_MemMove(cur, cur + next_off, end - (cur + next_off));

		obj->item_count--;
		obj->size -= next_off;
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

	return serializer_sync_head(obj);
}

/* Check attribute value matches provided blob */
bool serial_attribute_value_matches(struct sks_sobj_head *head, uint32_t attr,
				    void *value, size_t size)
{
	size_t count = 1;
	size_t attr_size;
	void *attr_value = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	void **attr_array = &attr_value;

	if (!attr_value)
		TEE_Panic(0);		/* FIXME: really panic? */

	serial_get_attributes_ptr(head, attr, attr_array, &attr_size, &count);

	return (count == 1 && attr_size == size &&
		!buf_compare_ct(value, attr_value, size));
}

/* Check attribute value matches provided blob */
bool serial_boolean_attribute_matches(struct sks_sobj_head *head,
				      uint32_t attr, bool value)
{
	uint8_t *ptr;

	/*
	 * Ref is sanitized, each boolean attribute set if consistent (unique).
	 * CK_BBOOL type is a byte, hence no alignement issue.
	 */
	serial_get_attribute_ptr(head, attr, (void **)&ptr, NULL);

	return !!*ptr == value;
}

size_t sizeof_serial_object_head(struct serializer *obj)
{
	(void)obj;

	return sizeof(struct sks_sobj_head);
}

size_t get_serial_object_size(struct serializer *obj)
{
	return sizeof_serial_object_head(obj) + obj->size;
}

uint32_t serializer_init(struct serializer *obj)
{
	struct sks_sobj_head head;

	TEE_MemFill(obj, 0, sizeof(*obj));

#ifdef SKS_SHEAD_WITH_TYPE
	obj->class = SKS_UNDEFINED_ID;
	obj->type = SKS_UNDEFINED_ID;
#endif

	/* Init serial buffer with a dummy head, will be fed at finalization */
	memset(&head, 0, sizeof(head));
	return serialize_buffer(obj, &head, sizeof(head));
}

uint32_t serializer_sync_head(struct serializer *obj)
{
	struct sks_sobj_head head;

	memset(&head, 0xff, sizeof(head));
	head.blobs_size = obj->size - sizeof(head);
	head.blobs_count = obj->item_count;

#ifdef SKS_SHEAD_WITH_TYPE
	head.object = obj->class;
	head.type = obj->type;
#endif
#ifdef SKS_SHEAD_WITH_BOOLPROPS
	head.boolpropl = obj->boolprop[0];
	head.boolproph = obj->boolprop[1];
#endif
	TEE_MemMove(obj->buffer, &head, sizeof(head));

	return SKS_OK;
}

void serializer_release_buffer(struct serializer *obj)
{
	TEE_Free(obj->buffer);
	obj->buffer = NULL;
}

void serializer_release(struct serializer *obj)
{
	if (!obj)
		return;

	serializer_release_buffer(obj);
	TEE_Free(obj);
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

uint32_t serialize_32b(struct serializer *obj, uint32_t data)
{
	return serialize(&obj->buffer, &obj->size, &data, sizeof(uint32_t));
}

uint32_t serialize_buffer(struct serializer *obj, void *data, size_t size)
{
	return serialize(&obj->buffer, &obj->size, data, size);
}

uint32_t serialize_sks_ref(struct serializer *obj,
			uint32_t id, void *data, size_t size)
{
	uint32_t rv;
	uint32_t ck_size = size;

	rv = serialize_32b(obj, id);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck_size);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, data, size);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
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
