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

/*
 * Trace content of the serialized object
 */
uint32_t trace_attributes_from_sobj_head(const char *prefix, void *ref);

#endif /*__SERIALIZER_H*/

