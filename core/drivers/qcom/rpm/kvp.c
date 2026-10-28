/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdbool.h>
#include <string.h>
#include <util.h>

#include "kvp.h"

#define KVP_ALIGN(n) ROUNDUP((n), 4)

void kvp_init(struct kvp *kvp, void *buffer, size_t capacity)
{
	kvp->buffer = buffer;
	kvp->capacity = capacity;
	kvp->size = 0;
	kvp->read_idx = 0;
}

void kvp_init_from_buffer(struct kvp *kvp, const void *buffer, size_t size)
{
	kvp->buffer = (uint8_t *)buffer;
	kvp->capacity = size;
	kvp->size = size;
	kvp->read_idx = 0;
}

void kvp_reset(struct kvp *kvp)
{
	kvp->read_idx = 0;
}

void kvp_clear(struct kvp *kvp)
{
	kvp->size = 0;
	kvp->read_idx = 0;
}

bool kvp_eof(const struct kvp *kvp)
{
	return kvp->read_idx >= kvp->size;
}

bool kvp_put(struct kvp *kvp, uint32_t type, uint32_t length,
	     const void *value)
{
	size_t padded_length = KVP_ALIGN(length);
	size_t needed = sizeof(type) + sizeof(length) + padded_length;
	uint8_t *dst = NULL;

	if (kvp->size + needed > kvp->capacity)
		return false;

	dst = kvp->buffer + kvp->size;

	memcpy(dst, &type, sizeof(type));
	dst += sizeof(type);
	memcpy(dst, &length, sizeof(length));
	dst += sizeof(length);

	if (length)
		memcpy(dst, value, length);
	if (padded_length > length)
		memset(dst + length, 0, padded_length - length);

	kvp->size += needed;

	return true;
}

static size_t kvp_bytes_available(const struct kvp *kvp)
{
	if (kvp->read_idx >= kvp->size)
		return 0;

	return kvp->size - kvp->read_idx;
}

bool kvp_get(struct kvp *kvp, uint32_t *type, uint32_t *length,
	     const uint8_t **value)
{
	const uint8_t *head = NULL;
	uint32_t raw_length = 0;

	if (kvp_bytes_available(kvp) < sizeof(*type) + sizeof(*length))
		return false;

	head = kvp->buffer + kvp->read_idx;
	memcpy(type, head, sizeof(*type));
	memcpy(&raw_length, head + sizeof(*type), sizeof(raw_length));
	kvp->read_idx += sizeof(*type) + sizeof(*length);

	*length = raw_length;

	if (!raw_length) {
		*value = NULL;
		return true;
	}

	if (kvp_bytes_available(kvp) < KVP_ALIGN(raw_length))
		return false;

	*value = kvp->buffer + kvp->read_idx;
	kvp->read_idx += KVP_ALIGN(raw_length);

	return true;
}

size_t kvp_get_raw_size(const struct kvp *kvp)
{
	return kvp->size;
}

const uint8_t *kvp_get_raw_bytes(const struct kvp *kvp)
{
	return kvp->buffer;
}
