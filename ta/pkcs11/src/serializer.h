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

/*
 * serialargs_init() - Initialize with a new input buffer
 * @args:	serializing state
 * @in:		input buffer
 * @size:	size of the input buffer
 */
void serialargs_init(struct serialargs *args, void *in, size_t size);

/*
 * serialargs_get() - copy out a chunk of data and advance
 * @args:	serializing state
 * @out:	output buffer
 * @sz:		number of bytes to copy to output buffer
 *
 * Returns PKCS11_CKR_OK on success or PKCS11_CKR_ARGUMENTS_BAD on failure.
 */
enum pkcs11_rc serialargs_get(struct serialargs *args, void *out, size_t sz);

/*
 * serialargs_get_u32() - copy out a uint32_t and advance
 * @args:	serializing state
 * @out:	output buffer
 *
 * Returns PKCS11_CKR_OK on success or PKCS11_CKR_ARGUMENTS_BAD on failure.
 */
static inline enum pkcs11_rc serialargs_get_u32(struct serialargs *args,
						uint32_t *out)
{
	return serialargs_get(args, out, sizeof(*out));
}

/*
 * serialargs_get_ptr() - get a pointer to a chunk of data and advance
 * @args:	serializing state
 * @out:	Pointer to the data retrieved in *@out
 * @size:	Number of bytes to advance
 *
 * Returns PKCS11_CKR_OK on success or PKCS11_CKR_ARGUMENTS_BAD on failure.
 */
enum pkcs11_rc serialargs_get_ptr(struct serialargs *args, void **out,
				  size_t size);

/*
 * serialargs_alloc_get_one_attribute() - allocate and extract one attribute
 * @args:	serializing state
 * @out:	Pointer to the allocated and extracted attribute in *@out
 *
 * Returns PKCS11_CKR_OK on success or an error code from enum pkcs11_rc on
 * failure.
 */
enum pkcs11_rc
serialargs_alloc_get_one_attribute(struct serialargs *args,
				   struct pkcs11_attribute_head **out);

/*
 * serialargs_alloc_get_attributes() - allocate and extract an object
 * @args:	serializing state
 * @out:	Pointer to the allocated and extracted object in *@out
 *
 * Returns PKCS11_CKR_OK on success or an error code from enum pkcs11_rc on
 * failure.
 */
enum pkcs11_rc serialargs_alloc_get_attributes(struct serialargs *args,
					       struct pkcs11_object_head **out);

/*
 * serialargs_alloc_and_get() - allocate and extract data
 * @args:	serializing state
 * @out:	Pointer to the allocated and extracted data in *@out
 * @size:	Number of bytes to extract
 *
 * Returns PKCS11_CKR_OK on success or an error code from enum pkcs11_rc on
 * failure.
 */
enum pkcs11_rc serialargs_alloc_and_get(struct serialargs *args,
					void **out, size_t size);

/*
 * serialargs_remaining_bytes() - check for remaining bytes
 * @args:	serializing state
 *
 * Returns true if there are remaining bytes in @args or false if all bytes
 * are consumed.
 */
bool serialargs_remaining_bytes(struct serialargs *args);

/*
 * serialargs_get_session_from_handle() - extract and verify session
 * @args:	serializing state
 * @client:	client state
 * @sess:	The retrieved session handle is available in *@sess
 *
 * Returns PKCS11_CKR_OK on success or an error code from enum pkcs11_rc on
 * failure.
 */
enum pkcs11_rc serialargs_get_session_from_handle(struct serialargs *args,
						  struct pkcs11_client *client,
						  struct pkcs11_session **sess);

/*
 * serialize() - append data into a serialized buffer
 * @bstart:	points to start of a buffer or NULL, *@bstart is updated
 *		with the new buffer if changed
 * @blen:	size of the *@bstart buffer, updated when data is added
 * @data:	data to appen to the buffer
 * @len:	size of the @data buffer
 *
 * Returns PKCS11_CKR_OK on success or an error code from enum pkcs11_rc on
 * failure.
 */
enum pkcs11_rc serialize(char **bstart, size_t *blen, void *data, size_t len);

#endif /*PKCS11_TA_SERIALIZER_H*/
