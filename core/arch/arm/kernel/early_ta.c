// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/early_ta.h>
#include <kernel/user_ta.h>
#include <kernel/user_ta_store.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <zlib.h>

struct user_ta_store_handle {
	const struct early_ta *early_ta;
	size_t offs;
	z_stream strm;
};

static const struct early_ta *find_early_ta(const TEE_UUID *uuid)
{
	const struct early_ta *ta;

	for_each_early_ta(ta)
		if (!memcmp(&ta->uuid, uuid, sizeof(*uuid)))
			return ta;

	return NULL;
}

static void *zalloc(void *opaque __unused, unsigned int items,
		    unsigned int size)
{
	return malloc(items * size);
}

static void zfree(void *opaque __unused, void *address)
{
	free(address);
}

static bool decompression_init(z_stream *strm,
			       const struct early_ta *ta)
{
	int st;

	strm->next_in = ta->ta;
	strm->avail_in = ta->size;
	strm->zalloc = zalloc;
	strm->zfree = zfree;
	st = inflateInit(strm);
	if (st != Z_OK) {
		EMSG("Decompression initialization error (%d)", st);
		return false;
	}

	return true;
}

static TEE_Result early_ta_open(const TEE_UUID *uuid,
				struct user_ta_store_handle **h)
{
	struct user_ta_store_handle *handle;
	const struct early_ta *ta;
	bool st;

	ta = find_early_ta(uuid);
	if (!ta)
		return TEE_ERROR_ITEM_NOT_FOUND;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ta->uncompressed_size) {
		st = decompression_init(&handle->strm, ta);
		if (!st) {
			free(handle);
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	handle->early_ta = ta;
	*h = handle;

	return TEE_SUCCESS;
}

static TEE_Result early_ta_get_size(const struct user_ta_store_handle *h,
				    size_t *size)
{
	const struct early_ta *ta = h->early_ta;

	if (ta->uncompressed_size)
		*size = ta->uncompressed_size;
	else
		*size = ta->size;

	return TEE_SUCCESS;
}

static TEE_Result early_ta_get_tag(const struct user_ta_store_handle *h,
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
	res = crypto_hash_update(ctx, h->early_ta->ta, h->early_ta->size);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, tag, *tag_len);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result read_uncompressed(struct user_ta_store_handle *h, void *data,
				    size_t len)
{
	uint8_t *src = (uint8_t *)h->early_ta->ta + h->offs;
	size_t next_offs = 0;

	if (ADD_OVERFLOW(h->offs, len, &next_offs) ||
	    next_offs > h->early_ta->size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data)
		memcpy(data, src, len);
	h->offs = next_offs;

	return TEE_SUCCESS;
}

static TEE_Result read_compressed(struct user_ta_store_handle *h, void *data,
				  size_t len)
{
	z_stream *strm = &h->strm;
	size_t total = 0;
	uint8_t *tmpbuf = NULL;
	TEE_Result ret;
	size_t out;
	int st;

	if (data) {
		strm->next_out = data;
		strm->avail_out = len;
	} else {
		/*
		 * inflate() does not support a NULL strm->next_out. So, to
		 * discard data, we have to allocate a temporary buffer. 1K
		 * seems reasonable.
		 */
		strm->avail_out = MIN(len, 1024U);
		tmpbuf = malloc(strm->avail_out);
		if (!tmpbuf) {
			EMSG("Out of memory");
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		strm->next_out = tmpbuf;
	}
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
		total += out;
		FMSG("%zu bytes", out);
		if (!data) {
			/*
			 * Reset the pointer to throw away what we've just read
			 * and read again as much as possible.
			 */
			strm->next_out = tmpbuf;
			strm->avail_out = MIN(len - total, 1024U);
		}
	} while ((st == Z_OK || st == Z_BUF_ERROR) && (total != len));
	if (st != Z_OK && st != Z_STREAM_END) {
		EMSG("Decompression error (%d)", st);
		ret = TEE_ERROR_GENERIC;
		goto out;
	}
	ret = TEE_SUCCESS;
out:
	free(tmpbuf);

	return ret;
}

static TEE_Result early_ta_read(struct user_ta_store_handle *h, void *data,
				size_t len)
{
	if (h->early_ta->uncompressed_size)
		return read_compressed(h, data, len);
	else
		return read_uncompressed(h, data, len);
}

static void early_ta_close(struct user_ta_store_handle *h)
{
	if (h->early_ta->uncompressed_size)
		inflateEnd(&h->strm);
	free(h);
}

TEE_TA_REGISTER_TA_STORE(2) = {
	.description = "early TA",
	.open = early_ta_open,
	.get_size = early_ta_get_size,
	.get_tag = early_ta_get_tag,
	.read = early_ta_read,
	.close = early_ta_close,
};

static TEE_Result early_ta_init(void)
{
	const struct early_ta *ta;
	char __maybe_unused msg[60] = { '\0', };

	for_each_early_ta(ta) {
		if (ta->uncompressed_size)
			snprintf(msg, sizeof(msg),
				 " (compressed, uncompressed %u)",
				 ta->uncompressed_size);
		else
			msg[0] = '\0';
		DMSG("Early TA %pUl size %u%s", (void *)&ta->uuid, ta->size,
		     msg);
	}

	return TEE_SUCCESS;
}

service_init(early_ta_init);
