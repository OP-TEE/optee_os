// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Shared CRYPTO0 CE block cipher helpers.
 */

#include <arm.h>
#include <ce.h>
#include <hwkm.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

/* Serializes all access to the shared CRYPTO0 CE cipher block. */
static struct mutex ce_mu = MUTEX_INITIALIZER;

#define CE_POLL_TIMEOUT_US	1000000U

void ce_lock(void)
{
	mutex_lock(&ce_mu);
}

void ce_unlock(void)
{
	mutex_unlock(&ce_mu);
}

vaddr_t ce_get_base(void)
{
	struct hwkm_drv_ctx *ctx = hwkm_get_context();

	if (!ctx || !ctx->crypto0_base)
		return 0;

	return ctx->crypto0_base + CE_REG_OFFSET;
}

/*
 * Write @key_len bytes of key into @nwords hardware registers starting at
 * @reg_base, zero-padding any remaining words beyond the key length.
 */
static void ce_write_key_words(vaddr_t base, uint32_t reg_base,
			       const uint8_t *key, size_t key_len,
			       unsigned int nwords)
{
	unsigned int i = 0;
	uint32_t w = 0;

	for (i = 0; i < nwords; i++) {
		if (i < key_len / CE_WORD_SIZE)
			memcpy(&w, key + i * CE_WORD_SIZE, CE_WORD_SIZE);
		else
			w = 0;

		io_write32_off(base, reg_base + i * CE_WORD_SIZE, w);
	}

	memzero_explicit(&w, sizeof(w));
}

void ce_load_key(vaddr_t base, const uint8_t *key, size_t key_len)
{
	ce_write_key_words(base, CE_ENCR_KEY(0), key, key_len,
			   CE_MAX_KEY_WORDS);
}

static const uint32_t ce_iv_regs[CE_IV_WORDS] = {
	CE_ENCR_IV0, CE_ENCR_IV1, CE_ENCR_IV2, CE_ENCR_IV3,
};

static const uint32_t ce_mask_regs[CE_IV_WORDS] = {
	CE_ENCR_CNTR_MASK0, CE_ENCR_CNTR_MASK1,
	CE_ENCR_CNTR_MASK2, CE_ENCR_CNTR_MASK3,
};

static void ce_write_iv(vaddr_t base, const uint8_t iv[TEE_AES_BLOCK_SIZE],
			const uint32_t masks[CE_IV_WORDS])
{
	unsigned int i = 0;
	uint32_t w = 0;

	for (i = 0; i < CE_IV_WORDS; i++) {
		memcpy(&w, iv + i * CE_WORD_SIZE, CE_WORD_SIZE);
		io_write32_off(base, ce_iv_regs[i], w);
		io_write32_off(base, ce_mask_regs[i], masks[i]);
	}
}

void ce_read_iv(vaddr_t base, uint8_t iv[TEE_AES_BLOCK_SIZE])
{
	unsigned int i = 0;
	uint32_t w = 0;

	for (i = 0; i < CE_IV_WORDS; i++) {
		w = io_read32_off(base, ce_iv_regs[i]);
		memcpy(iv + i * CE_WORD_SIZE, &w, CE_WORD_SIZE);
	}
}

/* Write the cipher engine's IV/counter register. */
void ce_load_iv(vaddr_t base, const uint8_t iv[TEE_AES_BLOCK_SIZE])
{
	static const uint32_t masks[CE_IV_WORDS] = {
		0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU,
	};

	ce_write_iv(base, iv, masks);
}

void ce_load_iv_gcm(vaddr_t base, const uint8_t iv[TEE_AES_BLOCK_SIZE])
{
	static const uint32_t masks[CE_IV_WORDS] = { 0, 0, 0, 0xffffffffU };

	ce_write_iv(base, iv, masks);
}

/* Post-completion status check. */
static TEE_Result ce_get_state(vaddr_t base)
{
	uint32_t s = io_read32_off(base, CE_STATUS);
	uint32_t s2 = io_read32_off(base, CE_STATUS2);
	TEE_Result res = TEE_SUCCESS;

	/* SW_ERR: OR of bits [19:15] - Any of these invalidate the result. */
	if (s & CE_STATUS_SW_ERR) {
		EMSG("qcom_ce: status error 0x%08" PRIx32, s);
		res = TEE_ERROR_GENERIC;
	}

	/* KEY_ERR: key equality or usage error; op was skipped. */
	if ((s2 & CE_STATUS2_KEY_ERR) && res == TEE_SUCCESS) {
		EMSG("qcom_ce: key error");
		res = TEE_ERROR_BAD_STATE;
	}

	return res;
}

uint32_t ce_encr_cfg(uint32_t mode, size_t key_len, bool encrypt)
{
	uint32_t cfg = 0;

	cfg  = (CE_ENCR_ALG_AES << CE_ENCR_SEG_CFG_ALG_SHIFT) &
	       CE_ENCR_SEG_CFG_ALG_MASK;

	cfg |= (mode << CE_ENCR_SEG_CFG_MODE_SHIFT) &
	       CE_ENCR_SEG_CFG_MODE_MASK;

	cfg |= ((key_len == 32 ? CE_KEY_SZ_AES256 : CE_KEY_SZ_AES128)
		<< CE_ENCR_SEG_CFG_KEY_SZ_SHIFT) &
	       CE_ENCR_SEG_CFG_KEY_SZ_MASK;

	if (encrypt)
		cfg |= CE_ENCR_SEG_CFG_ENCODE;

	return cfg;
}

uint32_t ce_encr_cfg_last(uint32_t mode, size_t key_len, bool encrypt)
{
	return ce_encr_cfg(mode, key_len, encrypt) | CE_ENCR_SEG_CFG_LAST;
}

/* Write one word to the DATA_IN FIFO port @port_i. */
static void ce_fifo_write(vaddr_t base, unsigned int port_i, uint32_t w)
{
	io_write32_off(base, CE_DATA_IN(port_i % CE_FIFO_PORTS), w);
}

/* Read one word from the DATA_OUT FIFO port @port_i. */
static uint32_t ce_fifo_read(vaddr_t base, unsigned int port_i)
{
	return io_read32_off(base, CE_DATA_OUT(port_i % CE_FIFO_PORTS));
}

static void ce_go(vaddr_t base)
{
	io_write32_off(base, CE_GOPROC, CE_GOPROC_GO);
	isb();
	/* STATUS read ensures GOPROC write reaches HW before polling. */
	(void)io_read32_off(base, CE_STATUS);
}

/* Return the number of words the DATA_IN FIFO can currently accept. */
static uint32_t ce_din_avail(uint32_t status)
{
	return ((status & CE_STATUS_DIN_SIZE_AVAIL) >>
		CE_STATUS_DIN_SIZE_AVAIL_SHIFT) / CE_WORD_SIZE;
}

/* Return the number of words currently available in the DATA_OUT FIFO. */
static uint32_t ce_dout_avail(uint32_t status)
{
	return ((status & CE_STATUS_DOUT_SIZE_AVAIL) >>
		CE_STATUS_DOUT_SIZE_AVAIL_SHIFT) / CE_WORD_SIZE;
}

uint32_t ce_auth_cfg(uint32_t mode, size_t key_len, bool encrypt,
		     bool first, bool last, size_t tag_len)
{
	uint32_t cfg = 0;

	cfg = (CE_AUTH_ALG_AES << CE_AUTH_SEG_CFG_ALG_SHIFT) &
	      CE_AUTH_SEG_CFG_ALG_MASK;

	cfg |= (mode << CE_AUTH_SEG_CFG_MODE_SHIFT) &
	       CE_AUTH_SEG_CFG_MODE_MASK;

	cfg |= ((key_len == 32 ? CE_KEY_SZ_AES256 : CE_KEY_SZ_AES128)
		<< CE_AUTH_SEG_CFG_KEY_SZ_SHIFT) &
	       CE_AUTH_SEG_CFG_KEY_SZ_MASK;

	/* AUTH_SIZE encodes tag length in bytes minus 1. */
	if (tag_len)
		cfg |= (((tag_len - 1) << CE_AUTH_SEG_CFG_SIZE_SHIFT) &
			CE_AUTH_SEG_CFG_SIZE_MASK);

	/* Auth after cipher on encrypt, before cipher on decrypt. */
	if (encrypt)
		cfg |= CE_AUTH_SEG_CFG_POS_AFTER;

	if (first)
		cfg |= CE_AUTH_SEG_CFG_FIRST;

	if (last)
		cfg |= CE_AUTH_SEG_CFG_LAST;

	return cfg;
}

void ce_load_auth_key(vaddr_t base, const uint8_t *key, size_t key_len)
{
	ce_write_key_words(base, CE_AUTH_KEY(0), key, key_len,
			   CE_MAX_AUTH_KEY_WORDS);
}

/* Write the authentication engine's GHASH accumulator register. */
void ce_load_auth_iv(vaddr_t base, const uint32_t auth_iv[CE_AUTH_IV_WORDS])
{
	unsigned int i = 0;

	for (i = 0; i < CE_AUTH_IV_WORDS; i++)
		io_write32_off(base, CE_AUTH_IV(i), auth_iv[i]);
}

void ce_read_auth_iv(vaddr_t base, uint32_t auth_iv[CE_AUTH_IV_WORDS])
{
	unsigned int i = 0;

	for (i = 0; i < CE_AUTH_IV_WORDS; i++)
		auth_iv[i] = io_read32_off(base, CE_AUTH_IV(i));
}

void ce_load_auth_byte_cnt(vaddr_t base, const uint32_t cnt[4])
{
	io_write32_off(base, CE_AUTH_BYTECNT0, cnt[0]);
	io_write32_off(base, CE_AUTH_BYTECNT1, cnt[1]);
	io_write32_off(base, CE_AUTH_BYTECNT2, cnt[2]);
	io_write32_off(base, CE_AUTH_BYTECNT3, cnt[3]);
}

void ce_read_auth_byte_cnt(vaddr_t base, uint32_t cnt[4])
{
	cnt[0] = io_read32_off(base, CE_AUTH_BYTECNT0);
	cnt[1] = io_read32_off(base, CE_AUTH_BYTECNT1);
	cnt[2] = io_read32_off(base, CE_AUTH_BYTECNT2);
	cnt[3] = io_read32_off(base, CE_AUTH_BYTECNT3);
}

void ce_load_info_nonce(vaddr_t base, const uint32_t nonce[4])
{
	unsigned int i = 0;

	for (i = 0; i < CE_IV_WORDS; i++)
		io_write32_off(base, CE_AUTH_INFO_NONCE(i), nonce[i]);
}

/* CIPHER. */

/*
 * ce_aes_xfer() - Encrypt or decrypt @len bytes (cipher-only).
 * Caller must load IV/key before. Call ce_read_iv() after to read back
 * the updated IV if needed (CBC: last ciphertext block).
 */
TEE_Result ce_aes_xfer(vaddr_t base, uint32_t encr_cfg,
		       const uint8_t *in, uint8_t *out, size_t len)
{
	uint32_t status = 0;
	uint32_t w = 0;
	/* @len is guarantee to be multiple of TEE_AES_BLOCK_SIZE. */
	unsigned int din_words = len / CE_WORD_SIZE;
	unsigned int dout_words = len / CE_WORD_SIZE;
	unsigned int din_done = 0;
	unsigned int dout_done = 0;
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	io_write32_off(base, CE_AUTH_SEG_CFG, 0);
	io_write32_off(base, CE_ENCR_SEG_SIZE, len);
	io_write32_off(base, CE_ENCR_SEG_START, 0);
	io_write32_off(base, CE_SEG_SIZE, len);
	io_write32_off(base, CE_ENCR_SEG_CFG, encr_cfg);

	/*
	 * Clear W0C error bits left over from any prior operation.
	 * STATUS[19:15] and STATUS2[29] (KEY_ERR) are sticky W0C.
	 */
	io_write32_off(base, CE_STATUS, 0);
	io_write32_off(base, CE_STATUS2, 0);

	ce_go(base);

	/* Interleaved DATA_IN write / DATA_OUT read loop. */
	timeout = timeout_init_us(CE_POLL_TIMEOUT_US);
	while (din_done < din_words || dout_done < dout_words) {
		uint32_t avail = 0;

		if (timeout_elapsed(timeout)) {
			memzero_explicit(out, len);
			return TEE_ERROR_BUSY;
		}

		status = io_read32_off(base, CE_STATUS);
		/* Exit early on error; ce_get_state() reports it. */
		if (status & CE_STATUS_SW_ERR)
			break;

		/* Write as many DATA_IN words as the FIFO has space for. */
		if ((status & CE_STATUS_DIN_RDY) && din_done < din_words) {
			uint32_t s2 = io_read32_off(base, CE_STATUS);
			unsigned int i = 0;

			avail = ce_din_avail(s2);
			while (avail && din_done < din_words) {
				memcpy(&w, in + din_done * sizeof(uint32_t),
				       sizeof(uint32_t));
				ce_fifo_write(base, i, w);

				din_done++;
				i++;
				avail--;
			}
		}

		/* Read as many DATA_OUT words as the FIFO contains. */
		if ((status & CE_STATUS_DOUT_RDY) && dout_done < dout_words) {
			uint32_t s2 = io_read32_off(base, CE_STATUS);
			unsigned int i = 0;

			avail = ce_dout_avail(s2);
			while (avail && dout_done < dout_words) {
				w = ce_fifo_read(base, i);
				memcpy(out + dout_done * sizeof(uint32_t),
				       &w, sizeof(uint32_t));
				dout_done++;
				i++;
				avail--;
			}
		}
	}

	/* Post-completion status check. */
	res = ce_get_state(base);
	if (res) {
		memzero_explicit(out, len);
		return res;
	}

	return TEE_SUCCESS;
}

/* AUTHENC. */

static TEE_Result aead_transfer(vaddr_t base, uint32_t encr_cfg,
				uint32_t auth_cfg,
				const uint8_t *in, uint8_t *out,
				size_t auth_start, size_t auth_len,
				size_t cipher_start, size_t cipher_len,
				uint8_t *tag, size_t tag_len, bool encrypt)
{
	/* For AAD-only or non-final payload segments, no tag. */
	size_t dec_tag = (tag_len && !encrypt) ? tag_len : 0;
	size_t enc_tag = (tag_len && encrypt) ? tag_len : 0;
	/*
	 * Callers pass either cipher_len = 0 (AAD-only) or
	 * auth_len = cipher_len (payload); the two are never independently
	 * non-zero and different.
	 */
	size_t din_pay = cipher_len ? cipher_len : auth_len;
	/* dec_tag bytes fed via DATA_IN are consumed for MAC comparison. */
	size_t din_bytes = din_pay + dec_tag;
	/*
	 * The engine always emits enc_tag tag bytes at the end of the final
	 * encrypt segment regardless of payload size. When the cipher engine
	 * is active it also emits cipher_len bytes of ciphertext;
	 * when idle (cipher_len = 0) the AAD bytes pass through.
	 */
	size_t dout_bytes = (cipher_len ? cipher_len : auth_len) + enc_tag;
	size_t seg_size = MAX(auth_start + auth_len,
			      cipher_start + cipher_len + dec_tag);

	size_t din_done = 0;
	size_t dout_done = 0;
	uint32_t status = 0;
	uint64_t timeout = 0;

	TEE_Result res = TEE_SUCCESS;

	io_write32_off(base, CE_AUTH_SEG_SIZE, auth_len);
	io_write32_off(base, CE_AUTH_SEG_START, auth_start);
	io_write32_off(base, CE_AUTH_SEG_CFG, auth_cfg);
	io_write32_off(base, CE_ENCR_SEG_SIZE, cipher_len + dec_tag);
	io_write32_off(base, CE_ENCR_SEG_START, cipher_start);
	io_write32_off(base, CE_SEG_SIZE, seg_size);
	io_write32_off(base, CE_ENCR_SEG_CFG, encr_cfg);

	/*
	 * Clear W0C error bits left over from any prior operation.
	 * STATUS[19:15] and STATUS2[29] (KEY_ERR) are sticky W0C.
	 */
	io_write32_off(base, CE_STATUS, 0);
	io_write32_off(base, CE_STATUS2, 0);

	ce_go(base);

	/*
	 * DATA_IN/DATA_OUT loop. Every byte clocked in passes through to
	 * DATA_OUT, so the loop always both feeds @din_bytes and drains
	 * @dout_bytes; leaving any DATA_OUT byte unread parks the engine in
	 * FINAL_READS and blocks OPERATION_DONE.
	 */
	timeout = timeout_init_us(CE_POLL_TIMEOUT_US);
	while (din_done < din_bytes || dout_done < dout_bytes) {
		uint32_t avail = 0;

		if (timeout_elapsed(timeout)) {
			if (out)
				memzero_explicit(out, cipher_len);
			return TEE_ERROR_BUSY;
		}

		status = io_read32_off(base, CE_STATUS);

		if ((status & CE_STATUS_DIN_RDY) && din_done < din_bytes) {
			uint32_t s2 = io_read32_off(base, CE_STATUS);
			unsigned int i = 0;

			avail = ce_din_avail(s2);
			while (avail && din_done < din_bytes) {
				uint8_t wb[sizeof(uint32_t)] = { };
				uint32_t w = 0;
				unsigned int b = 0;

				for (b = 0; b < sizeof(uint32_t) &&
				     din_done < din_bytes; b++, din_done++) {
					if (din_done < din_pay)
						wb[b] = in[din_done];
					else
						wb[b] = tag[din_done - din_pay];
				}
				memcpy(&w, wb, sizeof(w));
				ce_fifo_write(base, i, w);

				i++;
				avail--;
			}
		}

		if ((status & CE_STATUS_DOUT_RDY) && dout_done < dout_bytes) {
			uint32_t s2 = io_read32_off(base, CE_STATUS);
			unsigned int i = 0;

			avail = ce_dout_avail(s2);
			while (avail && dout_done < dout_bytes) {
				uint8_t wb[sizeof(uint32_t)] = { };
				uint32_t w = 0;
				unsigned int b = 0;

				w = ce_fifo_read(base, i);
				memcpy(wb, &w, sizeof(w));
				for (b = 0; b < sizeof(uint32_t) &&
				     dout_done < dout_bytes; b++, dout_done++) {
					if (dout_done < cipher_len)
						out[dout_done] = wb[b];
					else if (enc_tag)
						tag[dout_done - cipher_len] =
							wb[b];
				}
				i++;
				avail--;
			}
		}
	}

	/* Auth engine requires OPERATION_DONE poll. */
	timeout = timeout_init_us(CE_POLL_TIMEOUT_US);
	while (!(io_read32_off(base, CE_STATUS) & CE_STATUS_OPERATION_DONE)) {
		if (timeout_elapsed(timeout)) {
			if (out)
				memzero_explicit(out, cipher_len);
			return TEE_ERROR_BUSY;
		}
	}

	/*
	 * The engine compares the supplied tag internally and
	 * flags a mismatch in STATUS.MAC_FAILED. Report it as an invalid MAC.
	 */
	if (tag_len && !encrypt &&
	    (io_read32_off(base, CE_STATUS) & CE_STATUS_MAC_FAILED)) {
		if (out)
			memzero_explicit(out, cipher_len);
		return TEE_ERROR_MAC_INVALID;
	}

	res = ce_get_state(base);
	if (res && out)
		memzero_explicit(out, cipher_len);

	return res;
}

/*
 * ce_aes_aead_auth() - Feed @aad_len bytes of AAD through the auth engine.
 * Caller must load/save AUTH_IVn/AUTH_BYTECNTn around each call.
 */
TEE_Result ce_aes_aead_auth(vaddr_t base, uint32_t encr_cfg, uint32_t auth_cfg,
			    const uint8_t *aad, size_t aad_len)
{
	return aead_transfer(base, encr_cfg, auth_cfg, aad, NULL,
			     0, aad_len, aad_len, 0, NULL, 0, false);
}

/*
 * ce_aes_aead_xfer() - Encrypt/decrypt @len bytes with simultaneous auth.
 * Caller must load/save AUTH_IVn/AUTH_BYTECNTn around each call. On the
 * last segment, @tag/@tag_len carry the tag through the FIFO; pass tag_len=0
 * for non-final segments.
 */
TEE_Result ce_aes_aead_xfer(vaddr_t base, uint32_t encr_cfg,
			    uint32_t auth_cfg,
			    const uint8_t *in, uint8_t *out,
			    size_t len, uint8_t *tag, size_t tag_len,
			    bool encrypt)
{
	return aead_transfer(base, encr_cfg, auth_cfg, in, out,
			     0, len, 0, len, tag, tag_len, encrypt);
}
