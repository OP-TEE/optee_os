// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 NXP
 *
 * Implementation of Cipher GCM functions
 */
#include <caam_common.h>
#include <caam_desc_ccb_defines.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>

#include "local.h"

/*
 * Default GCM nonce length
 * CAAM Errata fix is used if nonce size is not the default one
 */
#define AES_GCM_DEFAULT_NONCE_LEN 12

/*
 * Context format in GCM mode
 */
struct gcm_caam_ctx_layout {
	/*
	 * 128 bits MAC value
	 */
	uint32_t mac[4];
	/*
	 * 128 bits Ctri value
	 */
	uint32_t yi[4];
	/*
	 * 128 bits Ctr0 value
	 */
	uint32_t y0[4];
};

/*
 * Update of the cipher operation of complete block except
 * last block. Last block can be partial block.
 *
 * @caam_ctx AE Cipher context
 * @encrypt  Encrypt or decrypt direction
 * @src      Source data to encrypt/decrypt
 * @dst      [out] Destination data encrypted/decrypted
 * @final    Last block flag
 */
static bool caam_ae_do_block_gcm(struct caam_ae_ctx *caam_ctx, bool encrypt,
				 struct caamdmaobj *src, struct caamdmaobj *dst,
				 bool final)
{
	/*
	 * CAAM Errata:
	 * When running GCM when the IV is not 12 bytes (96 bits),
	 * it is possible to "roll over" the 32-bit counter value.
	 * When this occurs (unless counter starts at -1),
	 * the AES operation will generate an incorrect MAC.
	 * This occurs even when -1 is used as the counter for the last block.
	 * The problem is that the 32-bit counter will overflow into the h
	 *  value, thus corrupting the MAC.
	 * In order to reliably work around this issue,
	 * the AES operation must be stopped after initialization to
	 * determine the counter value to see whether/when it will roll over.
	 * Then, before the offending block is processed,
	 * the context needs to be saved. The one block gets processed twice :
	 * GCM, restore MAC, GMAC over its ciphertext,
	 * then patch up the message and AAD lengths, and carry on as normal.
	 */
	uint32_t *desc = NULL;
	struct gcm_caam_ctx_layout ctx = { };
	size_t input_length = 0;
	uint32_t processed_blocks = 0;
	uint32_t counter_value = 0;
	uint32_t corrupted_block_size = 0;
	uint32_t yi_1s_complement = 0;
	uint32_t remaining_len = 0;

	if (!caam_ctx)
		return false;

	desc = caam_ctx->descriptor;

	/*
	 *  for encrypt:
	 *  1) Run GCM until we get to the block which will
	 *     roll over the counter.
	 *  2) Save the current ghash value
	 *  3) Encrypt that one block (creating a bad hash value)
	 *  4) Restore the hash value
	 *  5) Save current AAD len
	 *  6) Run ciphertext of the block in as AAD
	 *  7) Restore the AAD len
	 *  8) Run GCM on the rest of the message
	 *  9) Compute and store the MAC/tag
	 *
	 *  for decrypt:
	 *  1) Run GCM until we get to the block which will
	 *     roll over the counter.
	 *  2) Save the current ghash value
	 *  3) Decrypt that one block (creating a bad hash value)
	 *  4) Restore the hash value
	 *  5) Save current AAD len
	 *  6) Run ciphertext of the block in as AAD
	 *  7) Restore the AAD len
	 *  8) Run GCM on the rest of the message
	 *  9) Compute and store the MAC/tag
	 */

	if (!src || src->orig.length == 0 ||
	    caam_ctx->nonce.length == AES_GCM_DEFAULT_NONCE_LEN)
		return false;

	memcpy(&ctx, caam_ctx->ctx.data, sizeof(struct gcm_caam_ctx_layout));
	processed_blocks = TEE_U32_FROM_BIG_ENDIAN(ctx.yi[3]);
	input_length = src->orig.length;
	counter_value = processed_blocks + ROUNDUP_DIV(input_length, 16);

	/* check for overflow */
	if (counter_value >= processed_blocks)
		return false;

	assert(dst);

	yi_1s_complement = SHIFT_U32(UINT32_MAX - processed_blocks, 4);
	if ((yi_1s_complement + TEE_AES_BLOCK_SIZE) > input_length)
		corrupted_block_size = input_length - yi_1s_complement;
	else
		corrupted_block_size = TEE_AES_BLOCK_SIZE;
	remaining_len = input_length - (yi_1s_complement +
			corrupted_block_size);

	caam_desc_seq_out(desc, dst);
	caam_dmaobj_cache_push(dst);

	caam_desc_seq_in(desc, src);
	caam_dmaobj_cache_push(src);

	/* operation: cls1-op aes gcm update enc/dec */
	caam_desc_add_word(desc, CIPHER_UPDATE(caam_ctx->alg->type, encrypt));

	caam_desc_add_word(desc, FIFO_LD_SEQ(MSG, 0) | FIFO_STORE_EXT |
			   CMD_CLASS(CLASS_1) |
			   FIFO_LOAD_ACTION(LAST_C1));
	caam_desc_add_word(desc, yi_1s_complement);

	caam_desc_add_word(desc, FIFO_ST_SEQ(MSG_DATA, 0) | FIFO_STORE_EXT);
	caam_desc_add_word(desc, yi_1s_complement);

	/* jump: class1-done all-match[] always-jump offset=[01] local->[15] */
	caam_desc_add_word(desc,
			   JUMP_C1_LOCAL(ALL_COND_TRUE, JMP_COND(NONE), 1));

	/*
	 * move: class1-ctx+0 -> math2, len=TEE_AES_BLOCK_SIZE wait
	 * Save the current ghash value
	 */
	caam_desc_add_word(desc, MOVE_WAIT(C1_CTX_REG, MATH_REG2, 0,
					   TEE_AES_BLOCK_SIZE));

	/*
	 * ld: ind-clrw len=4 offs=0 imm
	 *     clrw: clr_c1mode clr_c1datas reset_cls1_done reset_cls1_cha
	 *	     clr_c2_ctx
	 */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_CLEAR_WRITTEN, 4));
	caam_desc_add_word(desc, CLR_WR_RST_C1_MDE | CLR_WR_RST_C1_DSZ |
				 CLR_WR_RST_C1_CHA | CLR_WR_RST_C1_DNE |
				 CLR_WR_RST_C2_CTX);

	/*
	 * Encrypt that one block (creating a bad hash value)
	 * operation: cls1-op aes gcm update enc/dec
	 */
	caam_desc_add_word(desc, CIPHER_UPDATE(caam_ctx->alg->type, encrypt));

	if (encrypt) {
		/* seqfifold: class1 msg-last1 len=corrupted_Block_Size */
		caam_desc_add_word(desc,
				   FIFO_LD_SEQ(MSG, corrupted_block_size) |
				   CMD_CLASS(CLASS_1) |
				   FIFO_LOAD_ACTION(LAST_C1));

		/* move: ofifo -> class2-ctx+0, len=corrupted_Block_Size wait */
		caam_desc_add_word(desc, MOVE_WAIT(OFIFO, C2_CTX_REG, 0,
						   corrupted_block_size));

		/* seqstr: ccb2 ctx len=vseqoutsz offs=0 */
		caam_desc_add_word(desc, ST_NOIMM_SEQ(CLASS_2, REG_CTX,
						      corrupted_block_size));
	} else {
		/* seqfifold: both msg-last2-last1 len=corrupted_Block_Size */
		caam_desc_add_word(desc,
				   FIFO_LD_SEQ(MSG, corrupted_block_size) |
				   CMD_CLASS(CLASS_DECO) |
				   FIFO_LOAD_ACTION(LAST_C1) |
				   FIFO_LOAD_ACTION(LAST_C2));

		/*
		 * move: class2-alnblk -> class2-ctx+0,
		 *	 len=corrupted_Block_Size (aux_ms)
		 */
		caam_desc_add_word(desc, MOVE(DECO_ALIGN, C2_CTX_REG, 0,
					      corrupted_block_size) |
					 MOVE_AUX(0x2));

		/* seqfifostr: msg len=vseqoutsz */
		caam_desc_add_word(desc,
				   FIFO_ST_SEQ(MSG_DATA, corrupted_block_size));
	}

	/* jump: class1-done all-match[] always-jump offset=[01] local->[23] */
	caam_desc_add_word(desc,
			   JUMP_C1_LOCAL(ALL_COND_TRUE, JMP_COND(NONE), 1));

	/*
	 * Restore the hash value
	 * move: math2 -> class1-ctx+0, len=TEE_AES_BLOCK_SIZE wait
	 */
	caam_desc_add_word(desc, MOVE_WAIT(MATH_REG2, C1_CTX_REG, 0,
					   TEE_AES_BLOCK_SIZE));

	/*
	 * ld: ind-clrw len=4 offs=0 imm
	 *     clrw: clr_c1mode clr_c1datas reset_cls1_done reset_cls1_cha
	 */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_CLEAR_WRITTEN, 4));
	caam_desc_add_word(desc, CLR_WR_RST_C1_MDE | CLR_WR_RST_C1_DSZ |
				 CLR_WR_RST_C1_CHA | CLR_WR_RST_C1_DNE);

	/*
	 * Save current AAD len
	 * move: class1-ctx+48 -> math2, len=8 wait
	 */
	caam_desc_add_word(desc, MOVE_WAIT(C1_CTX_REG, MATH_REG2, 48, 8));

	/*
	 * Run ciphertext of the block in as AAD
	 * move: class2-ctx+0 -> ififo, len=corrupted_Block_Size
	 */
	caam_desc_add_word(desc,
			   MOVE(C2_CTX_REG, IFIFO, 0, corrupted_block_size));

	/*
	 * ld: ind-nfsl len=4 offs=0 imm
	 * <nfifo_entry: ififo->class1 type=aad/pka1 lc1 len=16>
	 */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_NFIFO_n_SIZE,
					sizeof(uint32_t)));
	caam_desc_add_word(desc, NFIFO_NOPAD(C1, NFIFO_LC1, IFIFO, AAD,
					     corrupted_block_size));

	/* operation: cls1-op aes gcm update enc/dec */
	caam_desc_add_word(desc, CIPHER_UPDATE(caam_ctx->alg->type, encrypt));

	/* jump: class1-done all-match[] always-jump offset=[01] local->[32] */
	caam_desc_add_word(desc,
			   JUMP_C1_LOCAL(ALL_COND_TRUE, JMP_COND(NONE), 1));

	/*
	 * Restore the AAD len
	 * move: math2 -> class1-ctx+48, len=8 wait
	 */
	caam_desc_add_word(desc, MOVE_WAIT(MATH_REG2, C1_CTX_REG, 48, 8));

	/*
	 * Run GCM on the rest of the message
	 * ld: ind-clrw len=4 offs=0 imm
	 *     clrw: clr_c1mode clr_c1datas reset_cls1_done reset_cls1_cha
	 */
	caam_desc_add_word(desc, LD_IMM(CLASS_NO, REG_CLEAR_WRITTEN, 4));
	caam_desc_add_word(desc, CLR_WR_RST_C1_MDE | CLR_WR_RST_C1_DSZ |
				 CLR_WR_RST_C1_CHA | CLR_WR_RST_C1_DNE);

	if (final)
		caam_desc_add_word(desc,
				   CIPHER_FINAL(caam_ctx->alg->type, encrypt));
	else
		caam_desc_add_word(desc,
				   CIPHER_UPDATE(caam_ctx->alg->type, encrypt));

	/* ptr incremented by max. 7 */
	caam_desc_add_word(desc, FIFO_LD_SEQ(MSG, 0) | FIFO_STORE_EXT |
				 CMD_CLASS(CLASS_1) |
				 FIFO_LOAD_ACTION(LAST_C1));
	caam_desc_add_word(desc, remaining_len);

	caam_desc_add_word(desc, FIFO_ST_SEQ(MSG_DATA, 0) | FIFO_STORE_EXT);
	caam_desc_add_word(desc, remaining_len);

	return true;
}

TEE_Result caam_ae_initialize_gcm(struct drvcrypt_authenc_init *dinit)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_ae_ctx *caam_ctx = NULL;

	if (!dinit || !dinit->ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	caam_ctx = dinit->ctx;

	if (dinit->nonce.data && dinit->nonce.length) {
		retstatus = caam_cpy_buf(&caam_ctx->nonce, dinit->nonce.data,
					 dinit->nonce.length);
		AE_TRACE("Copy Nonce returned 0x%" PRIx32, retstatus);
		if (retstatus)
			return caam_status_to_tee_result(retstatus);
	}

	caam_ctx->do_block = caam_ae_do_block_gcm;

	/* Initialize the AAD buffer */
	caam_ctx->buf_aad.max = dinit->aad_len;

	return TEE_SUCCESS;
}

TEE_Result caam_ae_final_gcm(struct drvcrypt_authenc_final *dfinal)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caam_ae_ctx *caam_ctx = NULL;

	if (!dfinal)
		return TEE_ERROR_BAD_PARAMETERS;

	caam_ctx = dfinal->ctx;

	ret = caam_ae_do_update(caam_ctx, &dfinal->src, &dfinal->dst, true);
	if (ret)
		return ret;

	if (caam_ctx->tag_length) {
		if (dfinal->tag.length < caam_ctx->tag_length)
			return TEE_ERROR_BAD_PARAMETERS;

		if (caam_ctx->encrypt) {
			memcpy(dfinal->tag.data, caam_ctx->ctx.data,
			       caam_ctx->tag_length);
			dfinal->tag.length = caam_ctx->tag_length;
		} else {
			if (consttime_memcmp(dfinal->tag.data,
					     caam_ctx->ctx.data,
					     caam_ctx->tag_length))
				return TEE_ERROR_MAC_INVALID;
		}
	}

	return TEE_SUCCESS;
}
