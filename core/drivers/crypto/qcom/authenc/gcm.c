// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * AES-GCM AEAD context using the CRYPTO0 CE hardware.
 */

#include <ce.h>
#include <crypto/crypto_impl.h>
#include <io.h>
#include <malloc.h>
#include <string.h>
#include <string_ext.h>
#include "algorithms.h"

#define GCM_NONCE_LEN		12U
#define GCM_TAG_MIN		4U
#define GCM_TAG_MAX		16U

struct ce_gcm_ctx {
	struct crypto_authenc_ctx ctx;

	/*
	 * AES-192 is not supported by the CE hardware. When key_len == 24,
	 * sw_ctx points to a software GCM context that handles the operation.
	 * The dispatcher ops forward to sw_ctx when it is set.
	 */
	struct crypto_authenc_ctx *sw_ctx;

	uint8_t key[32];
	size_t key_len;

	bool encrypt;
	size_t tag_len;
	size_t aad_total;
	size_t payload_total;

	/*
	 * GCTR state. j0 is fixed for the lifetime of the operation.
	 * cipher_iv starts at J0+1 and advances after each payload segment.
	 */
	uint8_t j0[TEE_AES_BLOCK_SIZE];
	uint8_t cipher_iv[TEE_AES_BLOCK_SIZE];

	/*
	 * GHASH state saved in software between lock acquisitions so the
	 * hardware accumulator can be restored before each new segment.
	 */
	uint32_t auth_iv[CE_AUTH_IV_WORDS];
	uint32_t auth_byte_cnt[4];

	size_t aad_done;
	size_t payload_done;
	bool aad_flushed;

	/* True once any segment has been sent to hardware. */
	bool hw_started;

	/* Partial AAD buffer; padded and flushed before the first payload. */
	uint8_t aad_pad[TEE_AES_BLOCK_SIZE];
	size_t aad_pad_len;

	/*
	 * Partial payload state for byte-granular streaming.
	 *
	 * GCM requires block-aligned hardware transfers but must emit output
	 * for every input byte immediately (N bytes in -> N bytes out).
	 *
	 * When the last block of a segment is partial the driver:
	 *   1. Saves CE state (cipher_iv, auth_iv, auth_byte_cnt) from
	 *      BEFORE the partial block was sent - the "pre" snapshot.
	 *   2. Zero-pads the partial block to 16 bytes and sends it to HW.
	 *   3. Emits only the first part_len bytes of the ciphertext to dst.
	 *
	 * On the next update(), the pre snapshot is restored, the saved
	 * plaintext (part_pt) is prepended to the new data, and a new full
	 * block is sent. Only the new bytes' worth of output is emitted.
	 */
	uint8_t part_pt[TEE_AES_BLOCK_SIZE];
	size_t part_len;
	/* "pre" snapshot. */
	uint8_t pre_cipher_iv[TEE_AES_BLOCK_SIZE];
	uint32_t pre_auth_iv[CE_AUTH_IV_WORDS];
	uint32_t pre_auth_byte_cnt[4];
	size_t pre_payload_done;
};

static struct ce_gcm_ctx *to_gcm(struct crypto_authenc_ctx *ctx)
{
	return container_of(ctx, struct ce_gcm_ctx, ctx);
}

/* GCM-mode wrappers that bake in CE_ENCR/AUTH_MODE_GCM. */
static uint32_t gcm_ce_encr_cfg(size_t key_len, bool encrypt)
{
	return ce_encr_cfg(CE_ENCR_MODE_GCM, key_len, encrypt);
}

static uint32_t gcm_ce_encr_cfg_last(size_t key_len, bool encrypt)
{
	return ce_encr_cfg_last(CE_ENCR_MODE_GCM, key_len, encrypt);
}

static uint32_t gcm_ce_auth_cfg(size_t key_len, bool encrypt,
				bool first, bool last, size_t tag_len)
{
	return ce_auth_cfg(CE_AUTH_MODE_GCM, key_len, encrypt,
			   first, last, tag_len);
}

/*
 * HARDWARE PATH (AES-128 / AES-256).
 */

static TEE_Result gcm_derive_j0(const uint8_t *key, size_t key_len,
				const uint8_t *nonce, size_t nonce_len,
				uint8_t j0[TEE_AES_BLOCK_SIZE])
{
	vaddr_t base = ce_get_base();
	uint32_t auth_iv[CE_AUTH_IV_WORDS] = { };
	uint32_t auth_byte_cnt[4] = { };
	uint32_t encr_cfg = 0;
	uint32_t auth_cfg = 0;
	uint8_t block[TEE_AES_BLOCK_SIZE] = { };
	size_t off = 0;
	unsigned int i = 0;
	bool first = true;
	TEE_Result res = TEE_SUCCESS;

	io_write32_off(base, CE_CONFIG, CE_CONFIG_DEFAULT);
	ce_load_key(base, key, key_len);
	ce_load_auth_key(base, key, key_len);
	ce_load_auth_iv(base, auth_iv);
	ce_load_auth_byte_cnt(base, auth_byte_cnt);

	encr_cfg = gcm_ce_encr_cfg(key_len, false);

	while (off < nonce_len) {
		size_t n = MIN((size_t)TEE_AES_BLOCK_SIZE, nonce_len - off);

		memset(block, 0, sizeof(block));
		memcpy(block, nonce + off, n);
		auth_cfg = gcm_ce_auth_cfg(key_len, false, first, false, 0);
		res = ce_aes_aead_auth(base, encr_cfg, auth_cfg, block,
				       TEE_AES_BLOCK_SIZE);
		if (res)
			goto out;

		first = false;
		off += n;
	}

	memset(block, 0, sizeof(block));
	/* Final GHASH block: 0^64 || len64(IV) in bits, big-endian. */
	put_be64(block + 8, nonce_len * 8);
	auth_cfg = gcm_ce_auth_cfg(key_len, false, first, false, 0);
	res = ce_aes_aead_auth(base, encr_cfg, auth_cfg, block,
			       TEE_AES_BLOCK_SIZE);
	if (res)
		goto out;

	ce_read_auth_iv(base, auth_iv);
	for (i = 0; i < CE_IV_WORDS; i++)
		memcpy(j0 + i * CE_WORD_SIZE, &auth_iv[i], CE_WORD_SIZE);

out:
	memzero_explicit(block, sizeof(block));
	memzero_explicit(auth_iv, sizeof(auth_iv));

	return res;
}

static void gcm_hw_setup(struct ce_gcm_ctx *c, vaddr_t base)
{
	unsigned int i = 0;

	io_write32_off(base, CE_CONFIG, CE_CONFIG_DEFAULT);
	ce_load_key(base, c->key, c->key_len);
	ce_load_auth_key(base, c->key, c->key_len);

	for (i = 0; i < 4; i++) {
		uint32_t w = 0;

		memcpy(&w, c->j0 + i * 4, 4);
		io_write32_off(base, CE_ENCR_CCM_INIT_CNTR(i), w);
	}

	ce_load_iv_gcm(base, c->cipher_iv);
	ce_load_auth_iv(base, c->auth_iv);
	ce_load_auth_byte_cnt(base, c->auth_byte_cnt);
}

static TEE_Result gcm_init_hw(struct ce_gcm_ctx *c, TEE_OperationMode mode,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *nonce, size_t nonce_len,
			      size_t tag_len, size_t aad_len,
			      size_t payload_len)
{
	TEE_Result res = TEE_SUCCESS;

	if (key_len != 16 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!nonce_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (tag_len < GCM_TAG_MIN || tag_len > GCM_TAG_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(c->key, key, key_len);
	c->key_len = key_len;
	c->encrypt = (mode == TEE_MODE_ENCRYPT);
	c->tag_len = tag_len;
	c->aad_total = aad_len;
	c->payload_total = payload_len;

	if (nonce_len == GCM_NONCE_LEN) {
		/* 96-bit nonce: J0 = nonce || 0x000001 (NIST SP 800-38D). */
		memset(c->j0, 0, sizeof(c->j0));
		memcpy(c->j0, nonce, GCM_NONCE_LEN);
		c->j0[15] = 1;
	} else {
		ce_lock();
		res = gcm_derive_j0(key, key_len, nonce, nonce_len, c->j0);
		ce_unlock();
		if (res)
			return res;
	}

	memset(c->auth_iv, 0, sizeof(c->auth_iv));
	memset(c->auth_byte_cnt, 0, sizeof(c->auth_byte_cnt));
	memcpy(c->cipher_iv, c->j0, TEE_AES_BLOCK_SIZE);
	/* Big-endian byte order: bytes[12..15] are the counter word. */
	put_be32(c->cipher_iv + 12, get_be32(c->cipher_iv + 12) + 1);

	c->hw_started = false;
	c->aad_done = 0;
	c->payload_done = 0;
	c->aad_flushed = false;
	c->aad_pad_len = 0;
	c->part_len = 0;

	return TEE_SUCCESS;
}

/* AAD. */

static TEE_Result gcm_flush_aad_block(struct ce_gcm_ctx *c, vaddr_t base,
				      const uint8_t *block, bool first)
{
	uint32_t auth_cfg = 0;
	uint32_t encr_idle_cfg = 0;
	TEE_Result res = TEE_SUCCESS;

	/* ENCR_SEG_SIZE = 0 so the cipher engine is configured but is idle. */
	encr_idle_cfg = gcm_ce_encr_cfg(c->key_len, c->encrypt);
	auth_cfg = gcm_ce_auth_cfg(c->key_len, c->encrypt, first, false,
				   c->tag_len);
	res = ce_aes_aead_auth(base, encr_idle_cfg, auth_cfg, block,
			       TEE_AES_BLOCK_SIZE);
	if (!res) {
		ce_read_auth_iv(base, c->auth_iv);
		ce_read_auth_byte_cnt(base, c->auth_byte_cnt);
		c->hw_started = true;
	}

	return res;
}

/* Flush any remaining partial AAD, zero-padded to 16 bytes. */
static TEE_Result gcm_flush_remaining_aad(struct ce_gcm_ctx *c, vaddr_t base)
{
	TEE_Result res = TEE_SUCCESS;

	if (c->aad_flushed)
		return TEE_SUCCESS;

	if (c->aad_pad_len) {
		/* Zero-pad the partial block. */
		memset(c->aad_pad + c->aad_pad_len, 0,
		       TEE_AES_BLOCK_SIZE - c->aad_pad_len);
		res = gcm_flush_aad_block(c, base, c->aad_pad, !c->hw_started);
		if (res)
			return res;
		/* Not including the padding. */
		c->aad_done += c->aad_pad_len;
		c->aad_pad_len = 0;
	}

	c->aad_flushed = true;

	return TEE_SUCCESS;
}

static TEE_Result gcm_update_aad_hw(struct ce_gcm_ctx *c,
				    const uint8_t *data, size_t len)
{
	vaddr_t base = ce_get_base();
	size_t off = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!len)
		return TEE_SUCCESS;

	ce_lock();
	gcm_hw_setup(c, base);
	/*
	 * Process buffered partial block + new data in 16-byte chunks.
	 * A complete block is only flushed when more data follows; the last
	 * complete block stays in aad_pad so gcm_flush_remaining_aad() can
	 * send it with the LAST flag (or combined with the first payload).
	 */
	while (off < len) {
		size_t copy = MIN(len - off,
				  TEE_AES_BLOCK_SIZE - c->aad_pad_len);

		memcpy(c->aad_pad + c->aad_pad_len, data + off, copy);
		c->aad_pad_len += copy;
		off += copy;

		if (c->aad_pad_len == TEE_AES_BLOCK_SIZE && off < len) {
			res = gcm_flush_aad_block(c, base, c->aad_pad,
						  !c->hw_started);
			if (res)
				goto out;

			c->aad_done += TEE_AES_BLOCK_SIZE;
			c->aad_pad_len = 0;
		}
	}
out:
	ce_unlock();

	return res;
}

/* Ciphertext. */

/*
 * Send one 16-byte block to hardware (non-final).
 * Updates auth_iv/auth_byte_cnt/cipher_iv and payload_done.
 */
static TEE_Result gcm_send_block(struct ce_gcm_ctx *c, vaddr_t base,
				 uint32_t encr_cfg, const uint8_t *pt,
				 uint8_t *ct)
{
	uint32_t auth_cfg = 0;
	TEE_Result res = TEE_SUCCESS;

	auth_cfg = gcm_ce_auth_cfg(c->key_len, c->encrypt, !c->hw_started,
				   false, c->tag_len);
	res = ce_aes_aead_xfer(base, encr_cfg, auth_cfg, pt, ct,
			       TEE_AES_BLOCK_SIZE, NULL, 0, c->encrypt);
	if (!res) {
		ce_read_auth_iv(base, c->auth_iv);
		ce_read_auth_byte_cnt(base, c->auth_byte_cnt);
		ce_read_iv(base, c->cipher_iv);
		c->payload_done += TEE_AES_BLOCK_SIZE;
		c->hw_started = true;
	}

	return res;
}

static TEE_Result gcm_update_payload_hw(struct ce_gcm_ctx *c,
					const uint8_t *src, size_t len,
					uint8_t *dst)
{
	vaddr_t base = ce_get_base();
	uint32_t encr_cfg = 0;
	size_t src_off = 0;
	size_t dst_off = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!len)
		return TEE_SUCCESS;

	encr_cfg = gcm_ce_encr_cfg(c->key_len, c->encrypt);

	ce_lock();
	gcm_hw_setup(c, base);
	res = gcm_flush_remaining_aad(c, base);
	if (res)
		goto out;

	/*
	 * If there is a saved partial block, restore the CE state from before
	 * that partial block, then re-send (saved_pt || new_bytes) as a full
	 * block. Only the new_bytes portion of the ciphertext goes to dst;
	 * the saved portion was already emitted in the previous call.
	 */
	if (c->part_len) {
		uint8_t block_pt[TEE_AES_BLOCK_SIZE] = { };
		uint8_t block_ct[TEE_AES_BLOCK_SIZE] = { };
		size_t fill = MIN(len, TEE_AES_BLOCK_SIZE - c->part_len);

		/* Restore pre-partial state. */
		memcpy(c->cipher_iv, c->pre_cipher_iv, TEE_AES_BLOCK_SIZE);
		memcpy(c->auth_iv, c->pre_auth_iv, sizeof(c->auth_iv));
		memcpy(c->auth_byte_cnt, c->pre_auth_byte_cnt,
		       sizeof(c->auth_byte_cnt));
		c->payload_done = c->pre_payload_done;
		gcm_hw_setup(c, base);

		memcpy(block_pt, c->part_pt, c->part_len);
		memcpy(block_pt + c->part_len, src, fill);

		res = gcm_send_block(c, base, encr_cfg, block_pt, block_ct);
		memzero_explicit(block_pt, sizeof(block_pt));
		if (res)
			goto out;

		/* Emit only the new-bytes portion to dst. */
		memcpy(dst, block_ct + c->part_len, fill);
		memzero_explicit(block_ct, sizeof(block_ct));

		src_off += fill;
		dst_off += fill;

		if (src_off >= len) {
			/*
			 * Still partially filled after consuming all new bytes.
			 * Append the new bytes to the saved partial plaintext;
			 * the pre snapshot is unchanged so the next call
			 * re-sends from the same restored state.
			 */
			memcpy(c->part_pt + c->part_len, src, fill);
			c->part_len += fill;
			goto out;
		}

		c->part_len = 0;
	}

	/* Process remaining input in full 16-byte blocks. */
	while (src_off + TEE_AES_BLOCK_SIZE <= len) {
		uint8_t block_ct[TEE_AES_BLOCK_SIZE] = { };

		res = gcm_send_block(c, base, encr_cfg, src + src_off,
				     block_ct);
		if (res) {
			memzero_explicit(block_ct, sizeof(block_ct));
			goto out;
		}

		memcpy(dst + dst_off, block_ct, TEE_AES_BLOCK_SIZE);
		memzero_explicit(block_ct, sizeof(block_ct));
		src_off += TEE_AES_BLOCK_SIZE;
		dst_off += TEE_AES_BLOCK_SIZE;
	}

	/* Handle trailing partial block (< 16 bytes remaining). */
	if (src_off < len) {
		uint8_t block_pt[TEE_AES_BLOCK_SIZE] = { };
		uint8_t block_ct[TEE_AES_BLOCK_SIZE] = { };
		size_t tail = len - src_off;

		/* Snapshot CE state BEFORE sending the padded partial block. */
		memcpy(c->pre_cipher_iv, c->cipher_iv, TEE_AES_BLOCK_SIZE);
		memcpy(c->pre_auth_iv, c->auth_iv, sizeof(c->auth_iv));
		memcpy(c->pre_auth_byte_cnt, c->auth_byte_cnt,
		       sizeof(c->auth_byte_cnt));
		c->pre_payload_done = c->payload_done;

		memcpy(block_pt, src + src_off, tail);
		/* Zero-pad to full block. */

		res = gcm_send_block(c, base, encr_cfg, block_pt, block_ct);
		memzero_explicit(block_pt, sizeof(block_pt));
		if (res) {
			memzero_explicit(block_ct, sizeof(block_ct));
			goto out;
		}

		/* Emit only the real bytes to dst. */
		memcpy(dst + dst_off, block_ct, tail);

		/* Save partial state for next call. */
		memcpy(c->part_pt, src + src_off, tail);
		c->part_len = tail;
		memzero_explicit(block_ct, sizeof(block_ct));
	}
out:
	ce_unlock();

	return res;
}

/*
 * Process the final payload chunk (may be zero bytes).
 *
 * If a partial block was saved by update_payload(), the pre-partial CE state
 * is restored and the saved partial plaintext is prepended to @src so the
 * engine sees a single contiguous final buffer.
 *
 * The tag travels through the FIFO on this last segment: on encrypt the
 * computed tag is written to @tag; on decrypt @tag carries the caller's
 * expected tag into the engine, which compares it and reports a mismatch as
 * TEE_ERROR_MAC_INVALID. @tag must hold ROUND_UP(tag_len, 4) bytes because the
 * FIFO moves whole words.
 */
static TEE_Result gcm_do_final(struct ce_gcm_ctx *c, const uint8_t *src,
			       size_t len, uint8_t *dst, uint8_t *tag)
{
	vaddr_t base = ce_get_base();
	uint32_t encr_cfg = 0;
	uint32_t auth_cfg = 0;
	uint32_t info_nonce[4] = { };
	const uint8_t *xfer_src = src;
	uint8_t *xfer_dst = dst;
	size_t xfer_len = len;
	uint8_t *bounce_src = NULL;
	uint8_t *bounce_dst = NULL;
	TEE_Result res = TEE_SUCCESS;

	/*
	 * If there is a saved partial block, restore the pre-partial CE state
	 * and prepend the saved plaintext so the engine processes it together
	 * with the caller's final bytes in one LAST-flagged transfer.
	 */
	if (c->part_len) {
		xfer_len = c->part_len + len;
		if (xfer_len) {
			bounce_src = malloc(xfer_len);
			bounce_dst = malloc(xfer_len);
			if (!bounce_src || !bounce_dst) {
				free(bounce_src);
				free(bounce_dst);
				return TEE_ERROR_OUT_OF_MEMORY;
			}
			memcpy(bounce_src, c->part_pt, c->part_len);
			if (len)
				memcpy(bounce_src + c->part_len, src, len);
			xfer_src = bounce_src;
			xfer_dst = bounce_dst;
		}

		memcpy(c->cipher_iv, c->pre_cipher_iv, TEE_AES_BLOCK_SIZE);
		memcpy(c->auth_iv, c->pre_auth_iv, sizeof(c->auth_iv));
		memcpy(c->auth_byte_cnt, c->pre_auth_byte_cnt,
		       sizeof(c->auth_byte_cnt));
		c->payload_done = c->pre_payload_done;
	}

	encr_cfg = gcm_ce_encr_cfg_last(c->key_len, c->encrypt);

	ce_lock();

	gcm_hw_setup(c, base);
	res = gcm_flush_remaining_aad(c, base);
	if (res)
		goto out;

	auth_cfg = gcm_ce_auth_cfg(c->key_len, c->encrypt, !c->hw_started,
				   true, c->tag_len);

	{
		uint64_t aad_bits = (uint64_t)c->aad_done * 8;
		uint64_t pay_bits = (uint64_t)(c->payload_done + xfer_len) * 8;

		info_nonce[0] = TEE_U32_BSWAP((uint32_t)(aad_bits >> 32));
		info_nonce[1] = TEE_U32_BSWAP((uint32_t)(aad_bits &
							  0xffffffffU));
		info_nonce[2] = TEE_U32_BSWAP((uint32_t)(pay_bits >> 32));
		info_nonce[3] = TEE_U32_BSWAP((uint32_t)(pay_bits &
							  0xffffffffU));
	}

	ce_load_info_nonce(base, info_nonce);
	res = ce_aes_aead_xfer(base, encr_cfg, auth_cfg, xfer_src, xfer_dst,
			       xfer_len, tag, c->tag_len, c->encrypt);

	if (!res && bounce_dst && len)
		memcpy(dst, bounce_dst + c->part_len, len);
out:
	ce_unlock();

	if (bounce_src) {
		memzero_explicit(bounce_src, xfer_len);
		free(bounce_src);
	}

	if (bounce_dst) {
		memzero_explicit(bounce_dst, xfer_len);
		free(bounce_dst);
	}

	return res;
}

static TEE_Result gcm_enc_final_hw(struct ce_gcm_ctx *c, const uint8_t *src,
				   size_t len, uint8_t *dst, uint8_t *tag,
				   size_t *tag_len)
{
	uint8_t tag_buf[GCM_TAG_MAX] = { };
	TEE_Result res = TEE_SUCCESS;

	res = gcm_do_final(c, src, len, dst, tag_buf);
	if (res)
		return res;

	if (*tag_len < c->tag_len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(tag, tag_buf, c->tag_len);
	*tag_len = c->tag_len;

	return TEE_SUCCESS;
}

static TEE_Result gcm_dec_final_hw(struct ce_gcm_ctx *c, const uint8_t *src,
				   size_t len, uint8_t *dst, const uint8_t *tag,
				   size_t tag_len)
{
	uint8_t tag_buf[GCM_TAG_MAX] = { };

	if (tag_len != c->tag_len)
		return TEE_ERROR_MAC_INVALID;

	/*
	 * Feed the expected tag into the engine; it compares against the
	 * computed tag and gcm_do_final() maps a mismatch (STATUS.MAC_FAILED)
	 * to TEE_ERROR_MAC_INVALID. Copy into a word-padded buffer because the
	 * FIFO transfers whole words.
	 */
	memcpy(tag_buf, tag, tag_len);

	return gcm_do_final(c, src, len, dst, tag_buf);
}

/*
 * SOFTWARE PATH (AES-192).
 *
 * These forward directly to the software GCM context allocated in gcm_init().
 */

static TEE_Result gcm_init_sw(struct ce_gcm_ctx *c, TEE_OperationMode mode,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *nonce, size_t nonce_len,
			      size_t tag_len, size_t aad_len,
			      size_t payload_len)
{
	TEE_Result res = TEE_SUCCESS;

	res = crypto_aes_gcm_alloc_ctx(&c->sw_ctx);
	if (res)
		return res;

	res = c->sw_ctx->ops->init(c->sw_ctx, mode, key, key_len,
				   nonce, nonce_len, tag_len,
				   aad_len, payload_len);
	if (res) {
		c->sw_ctx->ops->free_ctx(c->sw_ctx);
		c->sw_ctx = NULL;
	}

	return res;
}

static TEE_Result gcm_update_aad_sw(struct ce_gcm_ctx *c,
				    const uint8_t *data, size_t len)
{
	return c->sw_ctx->ops->update_aad(c->sw_ctx, data, len);
}

static TEE_Result gcm_update_payload_sw(struct ce_gcm_ctx *c,
					TEE_OperationMode mode,
					const uint8_t *src, size_t len,
					uint8_t *dst)
{
	return c->sw_ctx->ops->update_payload(c->sw_ctx, mode, src, len, dst);
}

static TEE_Result gcm_enc_final_sw(struct ce_gcm_ctx *c, const uint8_t *src,
				   size_t len, uint8_t *dst, uint8_t *tag,
				   size_t *tag_len)
{
	return c->sw_ctx->ops->enc_final(c->sw_ctx, src, len, dst, tag,
					 tag_len);
}

static TEE_Result gcm_dec_final_sw(struct ce_gcm_ctx *c, const uint8_t *src,
				   size_t len, uint8_t *dst, const uint8_t *tag,
				   size_t tag_len)
{
	return c->sw_ctx->ops->dec_final(c->sw_ctx, src, len, dst, tag,
					 tag_len);
}

/*
 * DISPATCHERS.
 *
 * Each entry point selects the SW path (AES-192, sw_ctx set) or the HW path.
 */

static TEE_Result gcm_init(struct crypto_authenc_ctx *ctx,
			   TEE_OperationMode mode,
			   const uint8_t *key, size_t key_len,
			   const uint8_t *nonce, size_t nonce_len,
			   size_t tag_len, size_t aad_len,
			   size_t payload_len)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	/* Free any SW context left over from a previous init(). */
	if (c->sw_ctx) {
		c->sw_ctx->ops->free_ctx(c->sw_ctx);
		c->sw_ctx = NULL;
	}

	/* AES-192 is not supported by the CE hardware; use software GCM. */
	if (key_len == 24)
		return gcm_init_sw(c, mode, key, key_len, nonce, nonce_len,
				   tag_len, aad_len, payload_len);

	return gcm_init_hw(c, mode, key, key_len, nonce, nonce_len,
			   tag_len, aad_len, payload_len);
}

static TEE_Result gcm_update_aad(struct crypto_authenc_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	if (c->sw_ctx)
		return gcm_update_aad_sw(c, data, len);
	return gcm_update_aad_hw(c, data, len);
}

static TEE_Result gcm_update_payload(struct crypto_authenc_ctx *ctx,
				     TEE_OperationMode mode,
				     const uint8_t *src, size_t len,
				     uint8_t *dst)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	if (c->sw_ctx)
		return gcm_update_payload_sw(c, mode, src, len, dst);
	return gcm_update_payload_hw(c, src, len, dst);
}

static TEE_Result gcm_enc_final(struct crypto_authenc_ctx *ctx,
				const uint8_t *src, size_t len,
				uint8_t *dst, uint8_t *tag,
				size_t *tag_len)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	if (c->sw_ctx)
		return gcm_enc_final_sw(c, src, len, dst, tag, tag_len);
	return gcm_enc_final_hw(c, src, len, dst, tag, tag_len);
}

static TEE_Result gcm_dec_final(struct crypto_authenc_ctx *ctx,
				const uint8_t *src, size_t len,
				uint8_t *dst, const uint8_t *tag,
				size_t tag_len)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	if (c->sw_ctx)
		return gcm_dec_final_sw(c, src, len, dst, tag, tag_len);
	return gcm_dec_final_hw(c, src, len, dst, tag, tag_len);
}

static void gcm_final(struct crypto_authenc_ctx *ctx)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);
	const struct crypto_authenc_ops *ops = c->ctx.ops;
	struct crypto_authenc_ctx *saved_sw_ctx = c->sw_ctx;

	/*
	 * The SW final op only finalises; it does not free. Preserve the
	 * sw_ctx pointer across the memzero so gcm_free_ctx() (or a later
	 * gcm_init() re-init) can free it - otherwise the SW context leaks.
	 */
	if (saved_sw_ctx)
		saved_sw_ctx->ops->final(saved_sw_ctx);
	memzero_explicit(c, sizeof(*c));
	c->ctx.ops = ops;
	c->sw_ctx = saved_sw_ctx;
}

static void gcm_free_ctx(struct crypto_authenc_ctx *ctx)
{
	struct ce_gcm_ctx *c = to_gcm(ctx);

	if (c->sw_ctx)
		c->sw_ctx->ops->free_ctx(c->sw_ctx);
	memzero_explicit(c, sizeof(*c));
	free(c);
}

static void gcm_copy_state(struct crypto_authenc_ctx *dst_ctx,
			   struct crypto_authenc_ctx *src_ctx)
{
	struct ce_gcm_ctx *dst = to_gcm(dst_ctx);
	struct ce_gcm_ctx *src = to_gcm(src_ctx);

	/*
	 * If the source uses a SW context, delegate copy_state to the SW
	 * implementation. The destination must also have a SW context
	 * allocated; allocate one if it doesn't yet.
	 */
	if (src->sw_ctx) {
		if (!dst->sw_ctx)
			crypto_aes_gcm_alloc_ctx(&dst->sw_ctx);
		if (dst->sw_ctx)
			src->sw_ctx->ops->copy_state(dst->sw_ctx, src->sw_ctx);
		return;
	}

	/* HW path: plain struct copy; sw_ctx is NULL in both. */
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_authenc_ops gcm_ops = {
	.init = gcm_init,
	.update_aad = gcm_update_aad,
	.update_payload = gcm_update_payload,
	.enc_final = gcm_enc_final,
	.dec_final = gcm_dec_final,
	.final = gcm_final,
	.free_ctx = gcm_free_ctx,
	.copy_state = gcm_copy_state,
};

TEE_Result ce_aes_gcm_allocate(void **ctx)
{
	struct ce_gcm_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	c->ctx.ops = &gcm_ops;
	*ctx = &c->ctx;

	return TEE_SUCCESS;
}
