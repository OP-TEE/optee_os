/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIALIZER_H
#define __SERIALIZER_H

#include <sks_internal_abi.h>
#include <stdint.h>
#include <stddef.h>
#include <tee_internal_api.h>

/*
 * Util routines for serializes unformated arguments in a client memref
 */
struct serialargs {
	char *start;
	char *next;
	size_t size;
};

void serialargs_init(struct serialargs *args, void *in, size_t size);

/* Copies next ('size' bytes) into 'out' and increase next position. Return 0 on success, 1 on failure */
int serialargs_get_next(struct serialargs *args, void *out, size_t sz);

/* Return next argument address and and increase next position. Return 0 on success, 1 on failure */
void *serialargs_get_next_ptr(struct serialargs *args, size_t size);

/* Return the byte size of the remaning argument buffer */
size_t serialargs_remaining_size(struct serialargs *args);

int serialargs_get_sks_reference(struct serialargs *args,
				 struct sks_reference **out);

int serialargs_get_sks_attributes(struct serialargs *args,
				  struct sks_object_head **out);

#define SKS_MAX_BOOLPROP_SHIFT	64
#define SKS_MAX_BOOLPROP_ARRAY	(SKS_MAX_BOOLPROP_SHIFT / sizeof(uint32_t))

/*
 * Struct used to manage the memory buffer storing the serial object.
 * The structure also contains some fields to help parsing content.
 */
struct serializer {
	char *buffer;		/* serial buffer base address */
	size_t size;		/* serial buffer current byte size */
	size_t item_count;	/* number of items in entry table */
	uint32_t version;
	uint32_t config;
	uint32_t class;
	uint32_t type;
	uint32_t boolprop[SKS_MAX_BOOLPROP_ARRAY];
};

/* Return the byte size of the sks header */
size_t sizeof_serial_object_head(struct serializer *obj);
/* Return the byte size of the sks header */
size_t get_serial_object_size(struct serializer *obj);

/* Init/finalize/release a serializer object */
void serializer_reset(struct serializer *obj);
uint32_t serializer_init(struct serializer *obj);
uint32_t serializer_sync_head(struct serializer *obj);
void serializer_release_buffer(struct serializer *obj);
void serializer_release(struct serializer *obj);

/**
 * serialize - Append data into a serialized buffer
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len);
uint32_t serialize_32b(struct serializer *obj, uint32_t data);
uint32_t serialize_buffer(struct serializer *obj, void *data, size_t size);
uint32_t serialize_sks_ref(struct serializer *obj, uint32_t id, void *data,
			   size_t size);

/* Check attribute value matches provided blob */
bool serial_attribute_value_matches(struct sks_sobj_head *head, uint32_t attr,
				    void *value, size_t size);

/* Check attribute value matches provided blob */
bool serial_boolean_attribute_matches(struct sks_sobj_head *head,
				      uint32_t attr, bool value);

/* Return the number of items of the serial object (nb blobs after the head) */
size_t serial_get_count(void *ref);

/* Return the size of a serial object (head + blobs size) */
size_t serial_get_size(void *ref);

/* Return the class of the object or the invalid ID if not found */
uint32_t serial_get_class(void *ref);

/* Return the type of the object or the invalid ID if not found */
uint32_t serial_get_type(void *ref);

/*
 * serial_get_attribute_ptr - Get location of the target attribute
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr_ptr - output pointer to attribute data when found.
 * @attr_size - output byte size of the attribute data when found.
 *
 * Return CKR_OK if attribute is found, else return non CKR_OK.
 *
 * If attr_ptr is not null and attribute is found, attr_ptr will store the
 * attribute data location in memory.
 *
 * If attr_size is not null and attribute is found, attr_size will store the
 * byte size of the attribute data in memory.
 */
uint32_t serial_get_attribute_ptr(struct sks_sobj_head *head,
				  uint32_t attribute, void **attr_ptr,
				  size_t *attr_size);

/*
 * serial_get_attributes_ptr - Get count locations of target attribute
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr_ptr - output pointer to attribute data when found.
 * @attr_size - output byte size of the attribute data when found.
 * @count - input/ouptut count of attribute occurences.
 *
 * Count must be a valid pointer/reference. When *count is zero, the function
 * only counts the number of occurences of the attribute in the serial object.
 * When *count is not zero, it value defines how many occurrences we expect to
 * find.
 *
 * If attr_ptr is not null and attributes are found, each cell of attr_ptr
 * array will store the location (address) in memory of an occurence of the
 * target attribute.
 *
 * If attr_size is not null and attributes are found, each cell of attr_size
 * array will store the byte size in memory of an occurence of the target
 * attribute.
 *
 * Obviously the n'th cell referred by attr_ptr is related to the n'th cell
 * referred by attr_size.
 */
void serial_get_attributes_ptr(struct sks_sobj_head *head, uint32_t attribute,
				void **attr_ptr, size_t *attr_size, size_t *count);

/*
 * serial_get_attribute - Get target attribute data content
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr - NULL or output buffer where attribute data get copied to
 * @attr_size - NULL or pointer to the byte size of the attribute data
 *
 * Return a value different from CKR_OK if attribute is not found and cannot
 * be loaded in to attr and attr_size references.
 *
 * If attr is not null and attribute is found, attribute data get copied into
 * attr reference.
 *
 * If attr_size is not null and attribute is found, attr_size stores the byte
 * size in memory of the attribute data. Size must exacltly matches unless a
 *
 * FIXME: Unclear how to use this to check occurence (attr=attr_size=NULL) or
 * check occurrence and get attribute info (data and/or byte size).
 */
uint32_t serial_get_attribute(struct sks_sobj_head *head, uint32_t attribute,
			      void *attr, size_t *attr_size);

/*
 * serial_remove_attribute - Remove an attribute from a serialized object
 *
 * @ref - reference to serialized attribute
 * @attribute - ID of the attribute to remove
 *
 * Return SKS_OK on success, SKS_FAILED on error.
 */
uint32_t serializer_remove_attribute(struct serializer *obj,
				     uint32_t attribute);

/*
 * serializer_add_attribute - Add an attribute in a serialized object
 *
 * @ref - reference to serialized attribute
 * @attribute - ID of the attribute to remove
 * @data - pointer to the attribute data value
 * @size - byte size of the attribute data value
 *
 * Return SKS_OK on success, SKS_FAILED on error.
 */
uint32_t serializer_add_attribute(struct serializer *obj,
				  uint32_t attribute, void *data, size_t size);

/* Same from a attribute list head (may be relocated) */
uint32_t serial_add_attribute(struct sks_sobj_head **head,
			      uint32_t attribute, void *data, size_t size);

/*
 * Trace content of the serialized object
 */
uint32_t trace_attributes_from_sobj_head(const char *prefix, void *ref);

#endif /*__SERIALIZER_H*/

