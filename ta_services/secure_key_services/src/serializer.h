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

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				   void **out, size_t size);

// TODO: deprecate serialargs_get_next() and serialargs_get_next_ptr()
static inline uint32_t serialargs_get(struct serialargs *args,
				      void *out, size_t size)
{
	if (serialargs_get_next(args, out, size))
		return SKS_BAD_PARAM;

	return SKS_OK;
}

static inline uint32_t serialargs_get_ptr(struct serialargs *args,
					  void **out, size_t size)
{
	void *ptr = serialargs_get_next_ptr(args, size);

	if (!ptr)
		return SKS_BAD_PARAM;

	*out = ptr;

	return SKS_OK;
}

#define SKS_MAX_BOOLPROP_SHIFT	64
#define SKS_MAX_BOOLPROP_ARRAY	(SKS_MAX_BOOLPROP_SHIFT / sizeof(uint32_t))

/**
 * serialize - Append data into a serialized buffer
 */
uint32_t serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*__SERIALIZER_H*/

