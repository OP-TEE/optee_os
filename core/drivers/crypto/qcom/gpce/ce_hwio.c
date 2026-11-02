// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Implementation of Crypto Engine register access.
 */

#include <io.h>
#include <kernel/delay.h>
#include <string.h>
#include <util.h>

#include <tee_api_types.h>
#include <tee_api_defines.h>
#include "ce_hwio.h"
#include "hash.h"

#define CE_REG_DATA_IN(n)		(U(0x010) + (n) * U(4))
#define CE_REG_STATUS			U(0x100)
#define CE_REG_SEG_SIZE		U(0x110)
#define CE_REG_GOPROC			U(0x120)
#define CE_REG_ENCR_SEG_CFG		U(0x200)
#define CE_REG_AUTH_SEG_CFG		U(0x300)
#define CE_REG_AUTH_SEG_SIZE		U(0x304)
#define CE_REG_AUTH_SEG_START		U(0x308)
#define CE_REG_AUTH_IV(n)		(U(0x310) + (n) * U(4))
#define CE_REG_AUTH_BYTECNT(n)	(U(0x390) + (n) * U(4))
#define CE_REG_CONFIG			U(0x400)

#define CE_STATUS_AUTH_BUSY		BIT(8)
#define CE_STATUS_DIN_RDY		BIT(2)
#define CE_STATUS_OPERATION_DONE	BIT(1)
#define CE_STATUS_DIN_SIZE_AVAIL	GENMASK_32(25, 21)
#define CE_STATUS_DIN_SIZE_SHIFT	U(21)

#define CE_CONFIG_LITTLE_ENDIAN	BIT(9)
#define CE_CONFIG_HIGH_SPEED_DATA_EN_N	BIT(4)
#define CE_CONFIG_MASK_DIN_INTR	BIT(2)
#define CE_CONFIG_MASK_OP_DONE_INTR	BIT(1)

#define CE_AUTH_CFG_SHA		BIT(0)
#define CE_AUTH_CFG_LAST		BIT(16)
#define CE_AUTH_CFG_FIRST		BIT(17)
#define CE_GOPROC_GO			BIT(0)
#define CE_HWIO_BASE(dev)	((dev)->base)
#define CE_HWIO_FIFO_TIMEOUT_US	U(1000)
#define CE_HWIO_OPERATION_TIMEOUT_US	U(1000)

static void CE_HWIO_set_config(struct qce_hash_state *ctx, bool little)
{
	uint32_t cfg_msk = CE_CONFIG_HIGH_SPEED_DATA_EN_N |
			   CE_CONFIG_MASK_OP_DONE_INTR |
			   CE_CONFIG_MASK_DIN_INTR;

	if (little)
		cfg_msk |= CE_CONFIG_LITTLE_ENDIAN;

	io_write32(CE_HWIO_BASE(ctx->dev) + CE_REG_CONFIG, cfg_msk);
}

static TEE_Result CE_HWIO_get_ce_state(struct qce_hash_state *ctx)
{
	uint32_t ce_status = io_read32(CE_HWIO_BASE(ctx->dev) + CE_REG_STATUS);

	if (!(ce_status & CE_STATUS_OPERATION_DONE) ||
	    (ce_status & CE_STATUS_AUTH_BUSY))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

TEE_Result CE_HWIO_set_ce_ctx(struct qce_hash_state *ctx, size_t auth_sz,
			      size_t seg_sz, bool first, bool last)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
	/* Other algorithms may use fewer authentication byte counters. */
	size_t max_auth_byte_cnt = MAX_AUTH_BYTE_COUNT;
	size_t max_auth_iv_cnt = MAX_AUTH_IV_COUNT;
	uint32_t cfg = CE_AUTH_CFG_SHA;
	size_t i = 0;

	if (HASH_IS_CTX_NULL(ctx) ||
	    !ctx->ctx ||
	    ctx->ctx_sz != sizeof(*sha_ctx) || !ctx->dev)
		return TEE_ERROR_BAD_STATE;
	sha_ctx = HASH_GET_DIGEST_CTX(ctx, struct ce_sha_ctx_s);
	dev = ctx->dev;
	me = sha_ctx->ce_ctx;
	if (!me)
		return TEE_ERROR_BAD_STATE;

	/* CE HW Config set up */
	bool little_endian = CE_HAL_IS_FLAG_SET(me,
					   CE_HAL_FLAGS_IS_LITTLE_ENDIAN);

	CE_HWIO_set_config(ctx, little_endian);

	/* Auth engine set up */
	if (CE_HAL_IS_FLAG_SET(me, CE_HAL_FLAGS_IS_AUTH_ENG_EN)) {
		if (auth_sz > seg_sz)
			return TEE_ERROR_BAD_PARAMETERS;

		/* Authenticate the complete segment from offset zero. */
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_SEG_SIZE, auth_sz);
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_SEG_START, 0);
		io_write32(CE_HWIO_BASE(dev) + CE_REG_SEG_SIZE, seg_sz);

		for (i = 0; i < max_auth_iv_cnt; i++)
			io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_IV(i),
				   me->auth_iv[i]);

		/* Set ByteCounts */
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(0),
			   me->auth_byte_cnt[0]);
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(1),
			   me->auth_byte_cnt[1]);
		if (max_auth_byte_cnt == MAX_AUTH_BYTE_COUNT) {
			io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(2),
				   me->auth_byte_cnt[2]);
			io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(3),
				   me->auth_byte_cnt[3]);
		}

		if (last)
			cfg |= CE_AUTH_CFG_LAST;
		if (first)
			cfg |= CE_AUTH_CFG_FIRST;
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_SEG_CFG, cfg);
	} else {
		io_write32(CE_HWIO_BASE(dev) + CE_REG_AUTH_SEG_CFG, 0);
	}

	/* Cipher engine is disabled by the current hash-only driver. */
	io_write32(CE_HWIO_BASE(dev) + CE_REG_ENCR_SEG_CFG, 0);
	io_write32(CE_HWIO_BASE(dev) + CE_REG_GOPROC, CE_GOPROC_GO);
	dsb();

	/* Dummy read to flush out a posted write, if pending. */
	(void)io_read32(CE_HWIO_BASE(dev) + CE_REG_STATUS);

	return TEE_SUCCESS;
}

TEE_Result CE_HWIO_get_ce_ctx(struct qce_hash_state *ctx)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
	size_t max_auth_byte_cnt = MAX_AUTH_BYTE_COUNT;
	size_t max_auth_iv_cnt = MAX_AUTH_IV_COUNT;
	size_t i = 0;
	uint64_t timeout = 0;
	TEE_Result res = TEE_SUCCESS;

	if (HASH_IS_CTX_NULL(ctx) ||
	    !ctx->ctx ||
	    ctx->ctx_sz != sizeof(*sha_ctx) || !ctx->dev)
		return TEE_ERROR_BAD_STATE;
	sha_ctx = HASH_GET_DIGEST_CTX(ctx, struct ce_sha_ctx_s);
	dev = ctx->dev;
	me = sha_ctx->ce_ctx;
	if (!me)
		return TEE_ERROR_BAD_STATE;

	/* Auth Engine Context if enabled */
	if (CE_HAL_IS_FLAG_SET(me, CE_HAL_FLAGS_IS_AUTH_ENG_EN)) {
		timeout = timeout_init_us(CE_HWIO_OPERATION_TIMEOUT_US);
		while (true) {
			res = CE_HWIO_get_ce_state(ctx);
			if (res == TEE_SUCCESS)
				break;
			if (res != TEE_ERROR_BUSY)
				return res;
			if (timeout_elapsed(timeout))
				return TEE_ERROR_TIMEOUT;
		}

		/* Save IVs */
		for (i = 0; i < max_auth_iv_cnt; i++)
			me->auth_iv[i] =
				io_read32(CE_HWIO_BASE(dev) +
					  CE_REG_AUTH_IV(i));

		/* Save ByteCounts */
		me->auth_byte_cnt[0] =
			io_read32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(0));
		me->auth_byte_cnt[1] =
			io_read32(CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(1));
		if (max_auth_byte_cnt == MAX_AUTH_BYTE_COUNT) {
			vaddr_t reg = CE_HWIO_BASE(dev) +
				      CE_REG_AUTH_BYTECNT(2);

			me->auth_byte_cnt[2] = io_read32(reg);
			reg = CE_HWIO_BASE(dev) + CE_REG_AUTH_BYTECNT(3);
			me->auth_byte_cnt[3] = io_read32(reg);
		}
	}

	return CE_HWIO_get_ce_state(ctx);
}

TEE_Result CE_HWIO_xfer_data(struct qce_hash_state *ctx, const uint8_t *ibuf,
			     size_t isz)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
	size_t iwcnt = 0;

	if (HASH_IS_CTX_NULL(ctx) ||
	    !ctx->ctx ||
	    ctx->ctx_sz != sizeof(*sha_ctx) || !ctx->dev)
		return TEE_ERROR_BAD_STATE;
	sha_ctx = HASH_GET_DIGEST_CTX(ctx, struct ce_sha_ctx_s);
	dev = ctx->dev;
	me = sha_ctx->ce_ctx;
	if (!me)
		return TEE_ERROR_BAD_STATE;
	if (!ibuf && isz)
		return TEE_ERROR_BAD_PARAMETERS;

	iwcnt = ROUNDUP(isz, sizeof(uint32_t)) / sizeof(uint32_t);
	while (iwcnt) {
		uint64_t timeout = timeout_init_us(CE_HWIO_FIFO_TIMEOUT_US);
		uint32_t status = 0;
		size_t fifo_words = 0;
		size_t i = 0;

		while (true) {
			status = io_read32(CE_HWIO_BASE(dev) + CE_REG_STATUS);
			if (status & CE_STATUS_DIN_RDY)
				break;
			if (timeout_elapsed(timeout))
				return TEE_ERROR_TIMEOUT;
		}

		fifo_words = ((status & CE_STATUS_DIN_SIZE_AVAIL) >>
			      CE_STATUS_DIN_SIZE_SHIFT) / sizeof(uint32_t);
		for (i = 0; iwcnt && i < fifo_words; i++, iwcnt--) {
			uint32_t word = 0;
			size_t word_sz = MIN(isz, sizeof(word));

			/* Copy unaligned input and zero-pad a partial word. */
			memcpy(&word, ibuf, word_sz);
			io_write32(CE_HWIO_BASE(dev) + CE_REG_DATA_IN(i), word);
			ibuf += word_sz;
			isz -= word_sz;
		}
	}

	return TEE_SUCCESS;
}
