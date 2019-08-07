// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Implementation of Cipher XTS functions
 */
#include <caam_common.h>
#include <caam_utils_mem.h>
#include <mm/core_memprot.h>
#include <string.h>

#include "local.h"

/*
 * Galois Multiplication
 *
 * @buf  [in/out] buffer to multiply
 */
static void do_galois_mult(struct caambuf *buf)
{
	size_t idx = 0;
	uint8_t tmp = 0;
	uint8_t tmptmp = 0;

	for (idx = 0; idx < buf->length; idx++) {
		tmptmp = buf->data[idx] >> 7;
		buf->data[idx] = (buf->data[idx] << 1) | tmp;
		tmp = tmptmp;
	}

	if (tmptmp)
		buf->data[0] ^= 0x87;
}

/*
 * Tweak a cipher block (XTS mode)
 *
 * @ctx        Cipher context
 * @enc_tweak  [in/out] Encrypted tweak (Galois multiplication)
 * @srcbuf     Source data to encrypt/decrypt
 * @dstbuf     [out] Destination data encrypted/decrypted
 * @tmp        Temporary data buffer
 */
static enum caam_status do_tweak_block(struct cipherdata *ctx,
				       struct caambuf *enc_tweak,
				       struct caambuf *srcbuf,
				       struct caambuf *dstbuf,
				       struct caambuf *tmp)
{
	enum caam_status retstatus = CAAM_FAILURE;
	unsigned int idx = 0;

	/*
	 * TODO: Optimization by using CAAM to do it with MATH op in the
	 * operation description
	 */
	for (idx = 0; idx < ctx->alg->size_block; idx++)
		tmp->data[idx] = srcbuf->data[idx] ^ enc_tweak->data[idx];

	retstatus = caam_cipher_block(ctx, false, NEED_KEY1, ctx->encrypt, tmp,
				      tmp, false);

	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	for (idx = 0; idx < ctx->alg->size_block; idx++)
		dstbuf->data[idx] = tmp->data[idx] ^ enc_tweak->data[idx];

	/* Galois field multiplication of the tweak */
	do_galois_mult(enc_tweak);

	return retstatus;
}

TEE_Result caam_cipher_update_xts(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caambuf enc_tweak = { };
	struct caambuf tmpsrc = { };
	struct caambuf tmpdst = { };
	struct caambuf srcbuf = { };
	struct caambuf dstbuf = { };
	size_t idx = 0;
	size_t fullsize = 0;
	size_t lastblk = 0;
	paddr_t psrc = 0;
	paddr_t pdst = 0;

	CIPHER_TRACE("Algo AES XTS length=%zu - %s", dupdate->src.length,
		     ctx->encrypt ? "Encrypt" : " Decrypt");

	psrc = virt_to_phys(dupdate->src.data);
	pdst = virt_to_phys(dupdate->dst.data);

	/* Check the payload/cipher physical addresses */
	if (!psrc || !pdst) {
		CIPHER_TRACE("Bad Addr (src %#" PRIxPA ") (dst %#" PRIxPA ")",
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
		goto out;
	}

	retstatus = caam_cipher_block(ctx, false, NEED_KEY2, true, &ctx->tweak,
				      &enc_tweak, false);
	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("Tweak encryption error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	/*
	 * Encrypt or Decrypt input data.
	 * Check if the last block is partial or not
	 *  - if last block is partial, rebuild a complete
	 *    block using the penultimate complete block
	 *    encryption/decryption.
	 *  - else do all blocks.
	 */

	/* Calculate the number of complete block */
	fullsize = dupdate->src.length;
	lastblk = fullsize % ctx->alg->size_block;
	fullsize -= lastblk;

	/* One full block is needed */
	if (!fullsize) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (lastblk)
		fullsize -= ctx->alg->size_block;

	srcbuf.data = dupdate->src.data;
	srcbuf.length = ctx->alg->size_block;
	srcbuf.paddr = psrc;

	dstbuf.data = dupdate->dst.data;
	dstbuf.length = ctx->alg->size_block;
	dstbuf.paddr = pdst;

	for (; fullsize > 0; fullsize -= ctx->alg->size_block) {
		CIPHER_TRACE("Tweak block fullsize %zu", fullsize);
		retstatus = do_tweak_block(ctx, &enc_tweak, &srcbuf, &dstbuf,
					   &tmpdst);

		CIPHER_TRACE("Tweak block ret 0x%" PRIx32, retstatus);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}

		CIPHER_DUMPBUF("Source", srcbuf.data, srcbuf.length);
		CIPHER_DUMPBUF("Dest", dstbuf.data, dstbuf.length);

		/* Increment the source and destination block */
		srcbuf.data += ctx->alg->size_block;
		srcbuf.paddr += ctx->alg->size_block;

		dstbuf.data += ctx->alg->size_block;
		dstbuf.paddr += ctx->alg->size_block;
	}

	if (lastblk) {
		CIPHER_TRACE("Last block size is %zu", lastblk);

		/*
		 * Allocate the temporary buffer containing the
		 * penultimate block computed
		 */
		retstatus = caam_alloc_align_buf(&tmpsrc, ctx->alg->size_block);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (!ctx->encrypt) {
			/*
			 * In case of decryption, need to multiply
			 * the tweak first
			 */
			memcpy(tmpsrc.data, enc_tweak.data, enc_tweak.length);
			do_galois_mult(&tmpsrc);

			retstatus = do_tweak_block(ctx, &tmpsrc, &srcbuf,
						   &tmpdst, &tmpdst);
		} else {
			retstatus = do_tweak_block(ctx, &enc_tweak, &srcbuf,
						   &tmpdst, &tmpdst);
		}

		CIPHER_TRACE("Tweak penultimate block ret 0x%" PRIx32,
			     retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
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

		retstatus = do_tweak_block(ctx, &enc_tweak, &tmpsrc, &dstbuf,
					   &tmpdst);

		CIPHER_DUMPBUF("Source", tmpsrc.data, tmpsrc.length);
		CIPHER_DUMPBUF("Dest", dstbuf.data, dstbuf.length);
		CIPHER_TRACE("Tweak last block ret 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto out;
		}
	}

	/* Finalize by decrypting the tweak back */
	retstatus = caam_cipher_block(ctx, false, NEED_KEY2, false, &enc_tweak,
				      &ctx->tweak, false);
	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("Tweak decryption error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	caam_free_buf(&enc_tweak);
	caam_free_buf(&tmpsrc);
	caam_free_buf(&tmpdst);

	return ret;
}
