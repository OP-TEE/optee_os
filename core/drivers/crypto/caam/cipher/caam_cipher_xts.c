// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_cipher_xts.c
 *
 * @brief   CAAM Cipher XTS algorithm.\n
 *          Implementation of Cipher XTS functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>

/* Local includes */
#include "caam_common.h"
#include "local.h"

/* Utils includes */
#include "utils_mem.h"

/**
 * @brief   Galois Multiplication
 *
 * @param[in/out] buffer to multiply
 */
static void do_galois_mult(struct caambuf *buf)
{
	uint8_t idx;
	uint8_t tmp    = 0;
	uint8_t tmptmp = 0;


	for (idx = 0; idx < buf->length; idx++) {
		tmptmp         = buf->data[idx] >> 7;
		buf->data[idx] = ((buf->data[idx] << 1) | tmp) & 0xFF;
		tmp            = tmptmp;
	}

	if (tmptmp)
		buf->data[0] ^= 0x87;
}

/**
 * @brief   Tweak a cipher block (XTS mode)
 *
 * @param[in]     ctx       Cipher context
 * @param[in/out] enc_tweak Encrypted tweak
 * @param[in]     srcbuf    Source data to encrypt/decrypt
 * @param[out]    dstbuf    Destination data encrypted/decrypted
 * @param[in]     tmp       Temporary data buffer
 *
 * @retval CAAM_NO_ERROR  Success
 * @retval CAAM_FAILURE   Other Error
 */
static enum CAAM_Status do_tweak_block(struct cipherdata *ctx,
				struct caambuf *enc_tweak,
				struct caambuf *srcbuf,
				struct caambuf *dstbuf,
				struct sgtbuf *tmp)
{
	enum CAAM_Status retstatus;

	uint8_t idx;

	/* TODO: Build descriptor to do it with MATH op */
	for (idx = 0; idx < ctx->alg->size_block; idx++)
		tmp->buf->data[idx] = srcbuf->data[idx] ^ enc_tweak->data[idx];

	retstatus = do_block(ctx, false, NEED_KEY1, ctx->encrypt, tmp, tmp);

	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	for (idx = 0; idx < ctx->alg->size_block; idx++) {
		dstbuf->data[idx] = tmp->buf->data[idx] ^
		    enc_tweak->data[idx];
	}

	/* galois field multiplication of the tweak */
	do_galois_mult(enc_tweak);

	return retstatus;
}

/**
 * @brief   Update of the cipher operation in xts mode.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
TEE_Result do_update_xts(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct cipherdata *ctx = dupdate->ctx;

	struct caambuf enc_tweak = {0};

	struct caambuf tmpsrc = {0};
	struct caambuf tmpdst = {0};
	struct caambuf srcbuf = {0};
	struct caambuf dstbuf = {0};
	struct sgtbuf src = {0};
	struct sgtbuf tmp = {0};

	uint8_t idx;
	size_t  fullsize;
	size_t  lastblk;

	paddr_t psrc;
	paddr_t pdst;

	CIPHER_TRACE("Algo AES XTS length=%d - %s",
				dupdate->src.length,
				(ctx->encrypt ? "Encrypt" : " Decrypt"));

	psrc = virt_to_phys(dupdate->src.data);
	pdst = virt_to_phys(dupdate->dst.data);

	/* Check the payload/cipher physical addresses */
	if ((!psrc) || (!pdst)) {
		CIPHER_TRACE("Bad Addr (src 0x%"PRIxPA") (dst 0x%"PRIxPA")",
				psrc, pdst);
		return TEE_ERROR_GENERIC;
	}

	/* First operation is to encrypt the tweak with the key #2 */
	/* Allocate the encrypted tweak buffer */
	retstatus = caam_alloc_align_buf(&enc_tweak, ctx->tweak.length);
	if (retstatus != CAAM_NO_ERROR)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Allocate a temporary destination buffer to encrypt tweak block */
	retstatus = caam_alloc_align_buf(&tmpdst, ctx->alg->size_block);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_xts;
	}

	src.number   = 1;
	src.sgt_type = false;
	src.buf      = &ctx->tweak;
	tmp.number   = 1;
	tmp.sgt_type = false;
	tmp.buf      = &enc_tweak;

	retstatus = do_block(ctx, false, NEED_KEY2, true, &src, &tmp);
	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("Tweak encryption error");
		ret = TEE_ERROR_GENERIC;
		goto end_xts;
	}

	/*
	 * Encrypt or Decrypt input data.
	 * Check if the last block is partial or not
	 *  - if last block is partial, rebuild a complete
	 *    block using the penultimate complete block
	 *    encryption/decryption.
	 *
	 *  - else do all blocks.
	 *
	 */

	/* Calculate the number of complete block */
	fullsize  = dupdate->src.length;
	lastblk   = fullsize % ctx->alg->size_block;
	fullsize -= lastblk;

	/* One full block is needed */
	if (fullsize == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (lastblk)
		fullsize -= ctx->alg->size_block;

	srcbuf.data   = dupdate->src.data;
	srcbuf.length = ctx->alg->size_block;
	srcbuf.paddr  = psrc;

	dstbuf.data   = dupdate->dst.data;
	dstbuf.length = ctx->alg->size_block;
	dstbuf.paddr  = pdst;

	tmp.number   = 1;
	tmp.sgt_type = false;
	tmp.buf      = &tmpdst;

	while (fullsize > 0) {
		CIPHER_TRACE("Tweak block fullsize %d", fullsize);
		retstatus = do_tweak_block(ctx, &enc_tweak,
				&srcbuf, &dstbuf, &tmp);

		CIPHER_TRACE("Tweak block ret=0x%"PRIx32"", retstatus);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_xts;
		}

		CIPHER_DUMPBUF("Source", srcbuf.data, srcbuf.length);
		CIPHER_DUMPBUF("Dest", dstbuf.data, dstbuf.length);

		/* Increment the source and destination block */
		srcbuf.data  += ctx->alg->size_block;
		srcbuf.paddr += ctx->alg->size_block;

		dstbuf.data  += ctx->alg->size_block;
		dstbuf.paddr += ctx->alg->size_block;

		fullsize -= ctx->alg->size_block;
	}

	if (lastblk) {
		CIPHER_TRACE("Last block size is %d", lastblk);

		/*
		 * Allocate the temporary buffer containing the
		 * penultimate block computed
		 */
		retstatus = caam_alloc_align_buf(&tmpsrc, ctx->alg->size_block);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_xts;
		}

		if (!ctx->encrypt) {
			/*
			 * In case of decryption, need to multiply
			 * the tweak first
			 */
			memcpy(tmpsrc.data, enc_tweak.data, enc_tweak.length);
			do_galois_mult(&tmpsrc);

			retstatus = do_tweak_block(ctx, &tmpsrc,
					&srcbuf, &tmpdst, &tmp);
		} else
			retstatus = do_tweak_block(ctx, &enc_tweak,
				&srcbuf, &tmpdst, &tmp);

		CIPHER_TRACE("Tweak penultimate block ret=0x%"PRIx32"",
			retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_xts;
		}

		/* Build the last block and create the last destination block */
		for (idx = 0; idx < lastblk; idx++) {
			tmpsrc.data[idx] =
			    srcbuf.data[ctx->alg->size_block + idx];
			dstbuf.data[ctx->alg->size_block + idx] =
			    tmpdst.data[idx];
		}

		for (; idx < ctx->alg->size_block; idx++)
			tmpsrc.data[idx] = tmpdst.data[idx];

		retstatus = do_tweak_block(ctx, &enc_tweak,
				&tmpsrc, &dstbuf, &tmp);

		CIPHER_DUMPBUF("Source", tmpsrc.data, tmpsrc.length);
		CIPHER_DUMPBUF("Dest", dstbuf.data, dstbuf.length);
		CIPHER_TRACE("Tweak last block ret=0x%"PRIx32"", retstatus);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_xts;
		}
	}

	/* Finalize by decrypting the tweak back */
	src.buf = &enc_tweak;
	tmp.buf = &ctx->tweak;

	retstatus = do_block(ctx, false, NEED_KEY2, false, &src, &tmp);
	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("Tweak decryption error");
		ret = TEE_ERROR_GENERIC;
		goto end_xts;
	}

	ret = TEE_SUCCESS;

end_xts:
	caam_free_buf(&enc_tweak);
	caam_free_buf(&tmpsrc);
	caam_free_buf(&tmpdst);

	return ret;
}

