/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __ATTRIBUTES_H
#define __ATTRIBUTES_H

#include <assert.h>
#include <sks_internal_abi.h>
#include <stdint.h>
#include <stddef.h>

#include "sks_helpers.h"

/*
 * Return a SKS_OK on success or a SKS return code.
 */
uint32_t init_attributes_head(struct sks_attrs_head **head);

/*
 * Return a SKS_OK on success or a SKS return code.
 */
uint32_t add_attribute(struct sks_attrs_head **head,
			uint32_t attribute, void *data, size_t size);

/*
 * Return a SKS_OK on success or a SKS return code.
 */
uint32_t remove_attribute(struct sks_attrs_head **head, uint32_t attrib);

/*
 * Return a SKS_OK on success or a SKS return code.
 */
uint32_t remove_attribute_check(struct sks_attrs_head **head, uint32_t attrib,
				unsigned int max_check);

/*
 * If *count == 0, count and return in *count the number of attributes matching
 * the input attribute ID.
 *
 * If *count != 0, return the address and size of the attributes found, up to
 * the occurence number *conut. attr and attri_size and expected large
 * enougth. attr is the output array of the values found. attr_size is the
 * output array of the size of each values found.
 *
 * If attr_size != NULL, return in in *attr_size attribute value size .
 * If attr != NULL return in *attr the address in memory of the attribute value.
 */
void get_attribute_ptrs(struct sks_attrs_head *head, uint32_t attribute,
			void **attr, size_t *attr_size, size_t *count);

/*
 * If attributes is not found return SKS_NOT_FOUND.
 * If attr_size != NULL, return in in *attr_size attribute value size .
 * If attr != NULL return in *attr the address in memory of the attribute value.
 *
 * Return a SKS_OK or SKS_NOT_FOUND on success, or a SKS return code.
 */
uint32_t get_attribute_ptr(struct sks_attrs_head *head, uint32_t attribute,
			   void **attr_ptr, size_t *attr_size);
/*
 * If attributes is not found, rturn SKS_NOT_FOUND.
 * If attr_size != NULL, check *attr_size matches attributes size of return
 * SKS_SHORT_BUFFER with expected size in *attr_size.
 * If attr != NULL and attr_size is NULL or gives expected buffer size,
 * copy attribute value into attr.
 *
 * Return a SKS_OK or SKS_NOT_FOUND on success, or a SKS return code.
 */
uint32_t get_attribute(struct sks_attrs_head *head, uint32_t attribute,
			void *attr, size_t *attr_size);

/*
 * Some helpers
 */
static inline size_t attributes_size(struct sks_attrs_head *head)
{
	return sizeof(struct sks_attrs_head) + head->blobs_size;
}

#ifdef SKS_SHEAD_WITH_TYPE
static inline uint32_t get_class(struct sks_attrs_head *head)
{
	return head->class;
}

static inline uint32_t get_type(struct sks_attrs_head *head)
{
	return head->type;
}
#else
static inline uint32_t get_class(struct sks_attrs_head *head)
{
	uint32_t class;
	size_t size = sizeof(class);

	if (get_attribute(head, SKS_CLASS, &class, &size))
		return SKS_UNDEFINED_ID;

	return class;
}
static inline uint32_t get_type(struct sks_attrs_head *head)
{
	uint32_t type;
	size_t size = sizeof(type);

	if (get_attribute(head, SKS_TYPE, &type, &size))
		return SKS_UNDEFINED_ID;

	return type;
}
#endif

#ifdef SKS_SHEAD_WITH_BOOLPROPS
static inline bool get_bool(struct sks_attrs_head *head, uint32_t attribute)
{
	int shift = sks_attr2boolprop_shift(attribute);

	if (shift < 0)
		TEE_Panic(SKS_NOT_FOUND);

	if (shift > 31)
		return head->boolproph & BIT(shift - 32) ? true : false;
	else
		return head->boolpropl & BIT(shift) ? true : false;
}
#else
static inline bool get_bool(struct sks_attrs_head *head, uint32_t attribute)
{
	uint32_t rc __maybe_unused;
	uint8_t bbool;
	size_t size = sizeof(bbool);

	/* Would quicker reading from a bit field */
	rc = get_attribute(head, attribute, &bbool, &size);
	assert(rc == SKS_OK);

	return !!bbool;
}
#endif

/* Debug: dump object attributes to IMSG() trace console */
uint32_t trace_attributes(const char *prefix, void *ref);

#endif /*__ATTRIBUTES_H*/
