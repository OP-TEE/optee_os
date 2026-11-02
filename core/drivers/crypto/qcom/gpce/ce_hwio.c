// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
 *
 * Implementation of Crypto Engine register access.
 */

#include <io.h>
#include <string.h>
#include <util.h>

#include <tee_api_types.h>
#include <tee_api_defines.h>
#include "ce_hwio.h"
#include "hash.h"

#define CE_REG_VERSION			U(0x000)
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

#define CE_STATUS_HSD_ERR		BIT(20)
#define CE_STATUS_AUTH_BUSY		BIT(8)
#define CE_STATUS_DIN_RDY		BIT(2)
#define CE_STATUS_OPERATION_DONE	BIT(1)
#define CE_STATUS_SW_ERR		BIT(0)
#define CE_STATUS_ERR_INTR		BIT(4)
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

static void CE_HWIO_set_config(struct hash_ctx_s *ctx, bool little)
{
	uint32_t cfg_msk = CE_CONFIG_HIGH_SPEED_DATA_EN_N |
			   CE_CONFIG_MASK_OP_DONE_INTR |
			   CE_CONFIG_MASK_DIN_INTR;

	if (little)
		cfg_msk |= CE_CONFIG_LITTLE_ENDIAN;

	io_write32(CE_HWIO_BASE(ctx->dev) + CE_REG_CONFIG, cfg_msk);
}

static TEE_Result ce_hwio_get_ce_state(struct hash_ctx_s *ctx)
{
	uint32_t ce_status = io_read32(CE_HWIO_BASE(ctx->dev) + CE_REG_STATUS);

	if (ce_status & (CE_STATUS_ERR_INTR | CE_STATUS_SW_ERR |
			 CE_STATUS_HSD_ERR))
		return TEE_ERROR_GENERIC;
	if (!(ce_status & CE_STATUS_OPERATION_DONE) ||
	    (ce_status & CE_STATUS_AUTH_BUSY))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

TEE_Result CE_HWIO_set_ce_ctx(struct hash_ctx_s *ctx, size_t auth_sz,
			      size_t seg_sz, bool first, bool last)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
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
	bool little_endian = ce_hal_flag_set(me,
					   CE_HAL_FLAGS_IS_LITTLE_ENDIAN);

	CE_HWIO_set_config(ctx, little_endian);

	/* Auth engine set up */
	if (ce_hal_flag_set(me, CE_HAL_FLAGS_IS_AUTH_ENG_EN)) {
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

TEE_Result CE_HWIO_get_ce_ctx(struct hash_ctx_s *ctx)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
	size_t max_auth_byte_cnt = MAX_AUTH_BYTE_COUNT;
	size_t max_auth_iv_cnt = MAX_AUTH_IV_COUNT;
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

	/* Auth Engine Context if enabled */
	if (ce_hal_flag_set(me, CE_HAL_FLAGS_IS_AUTH_ENG_EN)) {
		/* Make sure operation is done before reading IV and ByteCnt. */
		while (!(io_read32(CE_HWIO_BASE(dev) + CE_REG_STATUS) &
			 CE_STATUS_OPERATION_DONE))
			;

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

	return ce_hwio_get_ce_state(ctx);
}

TEE_Result CE_HWIO_xfer_data(struct hash_ctx_s *ctx, const uint8_t *ibuf,
			     size_t isz)
{
	struct ce_sha_ctx_s *sha_ctx = NULL;
	struct qce_dev_s *dev = NULL;
	struct ce_ctx *me = NULL;
	size_t iwcnt = 0;
	bool is_ibuf_align = false;

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
	is_ibuf_align = IS_ALIGNED((uintptr_t)ibuf, sizeof(uint32_t));
	while (iwcnt) {
		uint32_t status = io_read32(CE_HWIO_BASE(dev) + CE_REG_STATUS);
		size_t fifo_words = 0;
		size_t i = 0;

		if (!(status & CE_STATUS_DIN_RDY))
			continue;

		fifo_words = ((status & CE_STATUS_DIN_SIZE_AVAIL) >>
			      CE_STATUS_DIN_SIZE_SHIFT) / sizeof(uint32_t);
		for (i = 0; iwcnt && i < fifo_words; i++, iwcnt--) {
			uint32_t word = 0;

			if (is_ibuf_align)
				memcpy(&word, ibuf, sizeof(word));
			else
				memcpy(&word, ibuf, sizeof(word));
			io_write32(CE_HWIO_BASE(dev) + CE_REG_DATA_IN(i), word);
			ibuf += sizeof(word);
		}
	}

	return TEE_SUCCESS;
}
