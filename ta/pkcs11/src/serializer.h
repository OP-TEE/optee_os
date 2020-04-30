/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_SERIALIZER_H
#define PKCS11_TA_SERIALIZER_H

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>

struct pkcs11_client;
struct pkcs11_session;

/*
 * Util routines for serializes unformated arguments in a client memref
 */
struct serialargs {
	char *start;
	char *next;
	size_t size;
};

struct pkcs11_client;
struct pkcs11_session;

void serialargs_init(struct serialargs *args, void *in, size_t size);

enum pkcs11_rc serialargs_get(struct serialargs *args, void *out, size_t sz);

enum pkcs11_rc serialargs_get_ptr(struct serialargs *args, void **out,
				  size_t size);

enum pkcs11_rc
serialargs_alloc_get_one_attribute(struct serialargs *args,
				   struct pkcs11_attribute_head **out);

enum pkcs11_rc serialargs_alloc_get_attributes(struct serialargs *args,
					       struct pkcs11_object_head **out);

enum pkcs11_rc serialargs_alloc_and_get(struct serialargs *args,
					void **out, size_t size);

bool serialargs_remaining_bytes(struct serialargs *args);

enum pkcs11_rc serialargs_get_session_from_handle(struct serialargs *args,
						  struct pkcs11_client *client,
						  struct pkcs11_session **sess);

/**
 * serialize - Append data into a serialized buffer
 */
enum pkcs11_rc serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*PKCS11_TA_SERIALIZER_H*/
