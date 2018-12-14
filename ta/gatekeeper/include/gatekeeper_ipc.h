/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#ifndef __GATEKEEPER_IPC_H
#define __GATEKEEPER_IPC_H

#include <stdint.h>
#include <string.h>

/*
 * Please keep this define consistent with TA_UUID variable that defined
 * in Android.mk file
 */
#define TA_GATEKEEPER_UUID { 0x4d573443, 0x6a56, 0x4272, \
		{ 0xac, 0x6f, 0x24, 0x25, 0xaf, 0x9e, 0xf9, 0xbb} }

/*
 * GateKeeper message size
 */
#define RECV_BUF_SIZE		8192

/*
 * GateKeeper command identifier
 */
enum gatekeeper_command {
	GK_ENROLL,
	GK_VERIFY,
};

/*
 * GateKeeper messages error codes
 */
enum gatekeeper_error {
	GK_ERROR_NONE = 0,
	GK_ERROR_INVALID,
	GK_ERROR_RETRY,
	GK_ERROR_UNKNOWN,
};

/*
 * General message functions
 */

/*
 * Size function. Function returns number of bytes that was used @buffer
 * through @iter
 *
 * @buffer points to the start of the data
 * @iter points to the end of read data
 * @return number of bytes
 */
static inline uint32_t get_size(const uint8_t *buffer, const uint8_t *iter)
{
	return iter - buffer;
}

/*
 * Serialization functions
 */

/*
 * Blob serialization function. Function writes to @buffer first
 * blob @length (4 bytes) and than writes blob @data (@length bytes).
 * After function @buffer will point to next memory after written data.
 *
 * @buffer that will contain serialized data
 * @data blob pointer
 * @length blob size
 */
static inline void serialize_blob(uint8_t **buffer,
				  const uint8_t *data,
				  uint32_t length)
{
	memcpy(*buffer, &length, sizeof(length));
	*buffer += sizeof(length);

	if (length) {
		memcpy(*buffer, data, length);
		*buffer += length;
	}
}

/*
 * Integer serialization function. Function writes to @buffer integer @data
 * (4 bytes). After function @buffer will point to next memory after
 * written data.
 *
 * @buffer that will contain serialized data
 * @data integer value
 */
static inline void serialize_int(uint8_t **buffer, uint32_t data)
{
	memcpy(*buffer, &data, sizeof(data));
	*buffer += sizeof(data);
}

/*
 * 64 bit integer serialization function. Function writes to @buffer integer
 * @data (8 bytes). After function @buffer will point to next memory after
 * written data.
 *
 * @buffer that will contain serialized data
 * @data 64 bit integer value
 */
static inline void serialize_int64(uint8_t **buffer, uint64_t data)
{
	memcpy(*buffer, &data, sizeof(data));
	*buffer += sizeof(data);
}

/*
 * Deserialization functions
 */

/*
 * Blob deserialization function. Function reads from @buffer first
 * blob length (4 bytes) and than reads blob data (length bytes).
 * After function @buffer will point to next memory after read data,
 * @data will point to deserialized blob and @length will contain @data length
 *
 * @buffer that contains serialized data
 * @data pointer that will point to deserialized blob
 * @length variable will contain blob length
 */
static inline void deserialize_blob(const uint8_t **buffer,
		const uint8_t **data, uint32_t *length)
{
	memcpy(length, *buffer, sizeof(*length));
	*buffer += sizeof(*length);
	if (*length) {
		*data = *buffer;
		*buffer += *length;
	} else {
		*data = NULL;
	}
}

/*
 * Integer deserialization function. Function reads from @buffer integer data
 * (4 bytes). This value will contain @data variable.
 * After function @buffer will point to next memory after read data,
 * @data will contain deserialized integer.
 *
 * @buffer that contains serialized data
 * @data variable that will contain deseriazed integer
 */
static inline void deserialize_int(const uint8_t **buffer, uint32_t *data)
{
	memcpy(data, *buffer, sizeof(*data));
	*buffer += sizeof(*data);
}

/*
 * 64 bit integer deserialization function. Function reads from @buffer integer
 * data (8 bytes). This value will contain @data variable.
 * After function @buffer will point to next memory after read data,
 * @data will contain deserialized 64 bit integer.
 *
 * @buffer that contains serialized data
 * @data variable that will contain deseriazed 64 bit integer
 */
static inline void deserialize_int64(const uint8_t **buffer, uint64_t *data)
{
	memcpy(data, *buffer, sizeof(*data));
	*buffer += sizeof(*data);
}

#endif /* __GATEKEEPER_IPC_H */
