// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/embedded_ts.h>
#include <kernel/ts_store.h>
#include <kernel/user_access.h>
#include <mempool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <zlib.h>

struct ts_store_handle {
	const struct embedded_ts *ts;
	size_t offs;
	z_stream strm;
};

static void *zalloc(void *opaque __unused, unsigned int items,
		    unsigned int size)
{
	return mempool_alloc(mempool_default, items * size);
}

static void zfree(void *opaque __unused, void *address)
{
	mempool_free(mempool_default, address);
}

static bool decompression_init(z_stream *strm,
			       const struct embedded_ts *ts)
{
	int st = Z_OK;

	strm->next_in = ts->ts;
	strm->avail_in = ts->size;
	strm->zalloc = zalloc;
	strm->zfree = zfree;
	st = inflateInit(strm);
	if (st != Z_OK) {
		EMSG("Decompression initialization error (%d)", st);
		return false;
	}

	return true;
}

TEE_Result emb_ts_open(const TEE_UUID *uuid,
		       struct ts_store_handle **h,
		       const struct embedded_ts*
		       (*find_ts) (const TEE_UUID *uuid))
{
	struct ts_store_handle *handle = NULL;
	const struct embedded_ts *ts = NULL;

	ts = find_ts(uuid);
	if (!ts)
		return TEE_ERROR_ITEM_NOT_FOUND;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ts->uncompressed_size) {
		if (!decompression_init(&handle->strm, ts)) {
			free(handle);
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	handle->ts = ts;
	*h = handle;

	return TEE_SUCCESS;
}

TEE_Result emb_ts_get_size(const struct ts_store_handle *h, size_t *size)
{
	const struct embedded_ts *ts = h->ts;

	if (ts->uncompressed_size)
		*size = ts->uncompressed_size;
	else
		*size = ts->size;

	return TEE_SUCCESS;
}

TEE_Result emb_ts_get_tag(const struct ts_store_handle *h,
			  uint8_t *tag, unsigned int *tag_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	if (!tag || *tag_len < TEE_SHA256_HASH_SIZE) {
		*tag_len = TEE_SHA256_HASH_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*tag_len = TEE_SHA256_HASH_SIZE;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;
	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, h->ts->ts, h->ts->size);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, tag, *tag_len);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result read_uncompressed(struct ts_store_handle *h, void *data_core,
				    void *data_user, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *src = (uint8_t *)h->ts->ts + h->offs;
	size_t next_offs = 0;

	if (ADD_OVERFLOW(h->offs, len, &next_offs) ||
	    next_offs > h->ts->size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data_core)
		memcpy(data_core, src, len);
	if (data_user)
		res = copy_to_user(data_user, src, len);
	if (!res)
		h->offs = next_offs;

	return res;
}

static TEE_Result read_compressed(struct ts_store_handle *h, void *data_core,
				  void *data_user, size_t len)
{
	TEE_Result res = TEE_SUCCESS;
	z_stream *strm = &h->strm;
	size_t total = 0;
	uint8_t *bb = NULL;
	size_t bb_len = 0;
	size_t out = 0;
	int st = Z_OK;

	/* Inflate into a 1kB bounce buffer */
	bb_len = MIN(len, 1024U);
	bb = bb_alloc(bb_len);
	if (!bb) {
		EMSG("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	strm->avail_out = bb_len;
	strm->next_out = bb;

	/*
	 * Loop until we get as many bytes as requested, or an error occurs.
	 * inflate() returns:
	 * - Z_OK when progress was made, but neither the end of the input
	 *   stream nor the end of the output buffer were met.
	 * - Z_STREAM_END when the end of the intput stream was reached.
	 * - Z_BUF_ERROR when there is still input to process but the output
	 *   buffer is full (not a "hard" error, decompression can proceeed
	 *   later).
	 */
	do {
		out = strm->total_out;
		st = inflate(strm, Z_SYNC_FLUSH);
		out = strm->total_out - out;
		FMSG("%zu bytes", out);
		if (data_core)
			memcpy((uint8_t *)data_core + total, bb, out);
		if (data_user) {
			res = copy_to_user((uint8_t *)data_user + total, bb,
					   out);
			if (res)
				goto out;
		}
		total += out;
		/*
		 * Reset the pointer since we've just copied out the last
		 * data.
		 */
		strm->next_out = bb;
		strm->avail_out = MIN(len - total, bb_len);
	} while ((st == Z_OK || st == Z_BUF_ERROR) && (total != len));

	if (st != Z_OK && st != Z_STREAM_END) {
		EMSG("Decompression error (%d)", st);
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	res = TEE_SUCCESS;
out:
	bb_free(bb, bb_len);

	return res;
}

TEE_Result emb_ts_read(struct ts_store_handle *h, void *data_core,
		       void *data_user, size_t len)
{
	if (h->ts->uncompressed_size)
		return read_compressed(h, data_core, data_user, len);
	else
		return read_uncompressed(h, data_core, data_user, len);
}

void emb_ts_close(struct ts_store_handle *h)
{
	if (h->ts->uncompressed_size)
		inflateEnd(&h->strm);
	free(h);
}

