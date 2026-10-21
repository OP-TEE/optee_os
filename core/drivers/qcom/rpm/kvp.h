/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#ifndef __RPM_KVP_H__
#define __RPM_KVP_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct kvp {
	uint8_t *buffer;
	size_t capacity;
	size_t size;
	size_t read_idx;
};

/* Bind a fixed caller-owned buffer for encoding (kvp_put()). */
void kvp_init(struct kvp *kvp, void *buffer, size_t capacity);

/*
 * Bind a fixed caller-owned buffer that already holds `size` bytes of
 * encoded data, for decoding (kvp_get()). Equivalent to the
 * reference's kvp_frombuffer()/kvp_swapbuffer().
 */
void kvp_init_from_buffer(struct kvp *kvp, const void *buffer, size_t size);

/* Reset the read cursor without touching data. */
void kvp_reset(struct kvp *kvp);

/* Discard all encoded data (encode-side only). */
void kvp_clear(struct kvp *kvp);

/* Nonzero when there are no more pairs left to read. */
bool kvp_eof(const struct kvp *kvp);

/*
 * Append one TLV entry. Returns false (and leaves the buffer
 * unmodified) if the entry would not fit in `capacity` -- unlike the
 * reference, this codec never reallocates.
 */
bool kvp_put(struct kvp *kvp, uint32_t type, uint32_t length,
	     const void *value);

/*
 * Read the next TLV entry. `*value` points directly into the kvp's
 * backing buffer and is valid only for the buffer's lifetime. Returns
 * false on EOF or a malformed/truncated entry.
 */
bool kvp_get(struct kvp *kvp, uint32_t *type, uint32_t *length,
	     const uint8_t **value);

size_t kvp_get_raw_size(const struct kvp *kvp);
const uint8_t *kvp_get_raw_bytes(const struct kvp *kvp);

#endif /* __RPM_KVP_H__ */
