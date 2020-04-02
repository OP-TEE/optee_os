/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_SERIALIZER_H
#define PKCS11_TA_SERIALIZER_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Util routines for serializes unformated arguments in a client memref
 */
struct serialargs {
	char *start;
	char *next;
	size_t size;
};

void serialargs_init(struct serialargs *args, void *in, size_t size);

uint32_t serialargs_get(struct serialargs *args, void *out, size_t sz);

uint32_t serialargs_get_ptr(struct serialargs *args, void **out, size_t size);

uint32_t serialargs_alloc_and_get(struct serialargs *args,
				  void **out, size_t size);

bool serialargs_remaining_bytes(struct serialargs *args);

#endif /*PKCS11_TA_SERIALIZER_H*/
