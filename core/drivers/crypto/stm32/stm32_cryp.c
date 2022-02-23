// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */
#include <assert.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/rstctrl.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/mutex.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <stm32_util.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

#include "stm32_cryp.h"
#include "common.h"

#define INT8_BIT			8U
#define AES_BLOCK_SIZE_BIT		128U
#define AES_BLOCK_SIZE			(AES_BLOCK_SIZE_BIT / INT8_BIT)
#define AES_BLOCK_NB_U32		(AES_BLOCK_SIZE / sizeof(uint32_t))
#define DES_BLOCK_SIZE_BIT		64U
#define DES_BLOCK_SIZE			(DES_BLOCK_SIZE_BIT / INT8_BIT)
#define DES_BLOCK_NB_U32		(DES_BLOCK_SIZE / sizeof(uint32_t))
#define MAX_BLOCK_SIZE_BIT		AES_BLOCK_SIZE_BIT
#define MAX_BLOCK_SIZE			AES_BLOCK_SIZE
#define MAX_BLOCK_NB_U32		AES_BLOCK_NB_U32
#define AES_KEYSIZE_128			16U
#define AES_KEYSIZE_192			24U
#define AES_KEYSIZE_256			32U

/* CRYP control register */
#define _CRYP_CR			0x0U
/* CRYP status register */
#define _CRYP_SR			0x04U
/* CRYP data input register */
#define _CRYP_DIN			0x08U
/* CRYP data output register */
#define _CRYP_DOUT			0x0CU
/* CRYP DMA control register */
#define _CRYP_DMACR			0x10U
/* CRYP interrupt mask set/clear register */
#define _CRYP_IMSCR			0x14U
/* CRYP raw interrupt status register */
#define _CRYP_RISR			0x18U
/* CRYP masked interrupt status register */
#define _CRYP_MISR			0x1CU
/* CRYP key registers */
#define _CRYP_K0LR			0x20U
#define _CRYP_K0RR			0x24U
#define _CRYP_K1LR			0x28U
#define _CRYP_K1RR			0x2CU
#define _CRYP_K2LR			0x30U
#define _CRYP_K2RR			0x34U
#define _CRYP_K3LR			0x38U
#define _CRYP_K3RR			0x3CU
/* CRYP initialization vector registers */
#define _CRYP_IV0LR			0x40U
#define _CRYP_IV0RR			0x44U
#define _CRYP_IV1LR			0x48U
#define _CRYP_IV1RR			0x4CU
/* CRYP context swap GCM-CCM registers */
#define _CRYP_CSGCMCCM0R		0x50U
#define _CRYP_CSGCMCCM1R		0x54U
#define _CRYP_CSGCMCCM2R		0x58U
#define _CRYP_CSGCMCCM3R		0x5CU
#define _CRYP_CSGCMCCM4R		0x60U
#define _CRYP_CSGCMCCM5R		0x64U
#define _CRYP_CSGCMCCM6R		0x68U
#define _CRYP_CSGCMCCM7R		0x6CU
/* CRYP context swap GCM registers */
#define _CRYP_CSGCM0R			0x70U
#define _CRYP_CSGCM1R			0x74U
#define _CRYP_CSGCM2R			0x78U
#define _CRYP_CSGCM3R			0x7CU
#define _CRYP_CSGCM4R			0x80U
#define _CRYP_CSGCM5R			0x84U
#define _CRYP_CSGCM6R			0x88U
#define _CRYP_CSGCM7R			0x8CU
/* CRYP hardware configuration register */
#define _CRYP_HWCFGR			0x3F0U
/* CRYP HW version register */
#define _CRYP_VERR			0x3F4U
/* CRYP identification */
#define _CRYP_IPIDR			0x3F8U
/* CRYP HW magic ID */
#define _CRYP_MID			0x3FCU

#define CRYP_TIMEOUT_US			1000000U
#define TIMEOUT_US_1MS			1000U

/* CRYP control register fields */
#define _CRYP_CR_RESET_VALUE		0x0U
#define _CRYP_CR_NPBLB_MSK		GENMASK_32(23, 20)
#define _CRYP_CR_NPBLB_OFF		20U
#define _CRYP_CR_GCM_CCMPH_MSK		GENMASK_32(17, 16)
#define _CRYP_CR_GCM_CCMPH_OFF		16U
#define _CRYP_CR_GCM_CCMPH_INIT		0U
#define _CRYP_CR_GCM_CCMPH_HEADER	1U
#define _CRYP_CR_GCM_CCMPH_PAYLOAD	2U
#define _CRYP_CR_GCM_CCMPH_FINAL	3U
#define _CRYP_CR_CRYPEN			BIT(15)
#define _CRYP_CR_FFLUSH			BIT(14)
#define _CRYP_CR_KEYSIZE_MSK		GENMASK_32(9, 8)
#define _CRYP_CR_KEYSIZE_OFF		8U
#define _CRYP_CR_KSIZE_128		0U
#define _CRYP_CR_KSIZE_192		1U
#define _CRYP_CR_KSIZE_256		2U
#define _CRYP_CR_DATATYPE_MSK		GENMASK_32(7, 6)
#define _CRYP_CR_DATATYPE_OFF		6U
#define _CRYP_CR_DATATYPE_NONE		0U
#define _CRYP_CR_DATATYPE_HALF_WORD	1U
#define _CRYP_CR_DATATYPE_BYTE		2U
#define _CRYP_CR_DATATYPE_BIT		3U
#define _CRYP_CR_ALGOMODE_MSK		(BIT(19) | GENMASK_32(5, 3))
#define _CRYP_CR_ALGOMODE_OFF		3U
#define _CRYP_CR_ALGOMODE_TDES_ECB	0x0U
#define _CRYP_CR_ALGOMODE_TDES_CBC	0x1U
#define _CRYP_CR_ALGOMODE_DES_ECB	0x2U
#define _CRYP_CR_ALGOMODE_DES_CBC	0x3U
#define _CRYP_CR_ALGOMODE_AES_ECB	0x4U
#define _CRYP_CR_ALGOMODE_AES_CBC	0x5U
#define _CRYP_CR_ALGOMODE_AES_CTR	0x6U
#define _CRYP_CR_ALGOMODE_AES		0x7U
#define _CRYP_CR_ALGOMODE_AES_GCM	BIT(16)
#define _CRYP_CR_ALGOMODE_AES_CCM	(BIT(16) | BIT(0))
#define _CRYP_CR_ALGODIR		BIT(2)
#define _CRYP_CR_ALGODIR_ENC		0U
#define _CRYP_CR_ALGODIR_DEC		BIT(2)

/* CRYP status register fields */
#define _CRYP_SR_BUSY			BIT(4)
#define _CRYP_SR_OFFU			BIT(3)
#define _CRYP_SR_OFNE			BIT(2)
#define _CRYP_SR_IFNF			BIT(1)
#define _CRYP_SR_IFEM			BIT(0)

/* CRYP DMA control register fields */
#define _CRYP_DMACR_DOEN		BIT(1)
#define _CRYP_DMACR_DIEN		BIT(0)

/* CRYP interrupt fields */
#define _CRYP_I_OUT			BIT(1)
#define _CRYP_I_IN			BIT(0)

/* CRYP hardware configuration register fields */
#define _CRYP_HWCFGR_CFG1_MSK		GENMASK_32(3, 0)
#define _CRYP_HWCFGR_CFG1_OFF		0U
#define _CRYP_HWCFGR_CFG2_MSK		GENMASK_32(7, 4)
#define _CRYP_HWCFGR_CFG2_OFF		4U
#define _CRYP_HWCFGR_CFG3_MSK		GENMASK_32(11, 8)
#define _CRYP_HWCFGR_CFG3_OFF		8U
#define _CRYP_HWCFGR_CFG4_MSK		GENMASK_32(15, 12)
#define _CRYP_HWCFGR_CFG4_OFF		12U

/* CRYP HW version register */
#define _CRYP_VERR_MSK			GENMASK_32(7, 0)
#define _CRYP_VERR_OFF			0U

/*
 * Macro to manage bit manipulation when we work on local variable
 * before writing only once to the real register.
 */
#define CLRBITS(v, bits)		((v) &= ~(bits))
#define SETBITS(v, bits)		((v) |= (bits))

#define IS_ALGOMODE(cr, mod) \
	(((cr) & _CRYP_CR_ALGOMODE_MSK) == (_CRYP_CR_ALGOMODE_##mod << \
					  _CRYP_CR_ALGOMODE_OFF))

#define SET_ALGOMODE(mod, cr) \
	clrsetbits(&(cr), _CRYP_CR_ALGOMODE_MSK, (_CRYP_CR_ALGOMODE_##mod << \
						  _CRYP_CR_ALGOMODE_OFF))

#define GET_ALGOMODE(cr) \
	(((cr) & _CRYP_CR_ALGOMODE_MSK) >> _CRYP_CR_ALGOMODE_OFF)

#define TOBE32(x)			TEE_U32_BSWAP(x)
#define FROMBE32(x)			TEE_U32_BSWAP(x)

static struct stm32_cryp_platdata cryp_pdata;
static struct mutex cryp_lock = MUTEX_INITIALIZER;

static void clrsetbits(uint32_t *v, uint32_t mask, uint32_t bits)
{
	*v = (*v & ~mask) | bits;
}

static bool algo_mode_needs_iv(uint32_t cr)
{
	return !IS_ALGOMODE(cr, TDES_ECB) && !IS_ALGOMODE(cr, DES_ECB) &&
	       !IS_ALGOMODE(cr, AES_ECB);
}

static bool algo_mode_is_ecb_cbc(uint32_t cr)
{
	return GET_ALGOMODE(cr) < _CRYP_CR_ALGOMODE_AES_CTR;
}

static bool algo_mode_is_aes(uint32_t cr)
{
	return ((cr & _CRYP_CR_ALGOMODE_MSK) >> _CRYP_CR_ALGOMODE_OFF) >=
	       _CRYP_CR_ALGOMODE_AES_ECB;
}

static bool is_decrypt(uint32_t cr)
{
	return (cr & _CRYP_CR_ALGODIR) == _CRYP_CR_ALGODIR_DEC;
}

static bool is_encrypt(uint32_t cr)
{
	return !is_decrypt(cr);
}

static bool does_need_npblb(uint32_t cr)
{
	return (IS_ALGOMODE(cr, AES_GCM) && is_encrypt(cr)) ||
	       (IS_ALGOMODE(cr, AES_CCM) && is_decrypt(cr));
}

static TEE_Result wait_sr_bits(vaddr_t base, uint32_t bits)
{
	uint64_t timeout_ref = timeout_init_us(CRYP_TIMEOUT_US);

	while ((io_read32(base + _CRYP_SR) & bits) != bits)
		if (timeout_elapsed(timeout_ref))
			break;

	if ((io_read32(base + _CRYP_SR) & bits) != bits)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result wait_end_busy(vaddr_t base)
{
	uint64_t timeout_ref = timeout_init_us(CRYP_TIMEOUT_US);

	while (io_read32(base + _CRYP_SR) & _CRYP_SR_BUSY)
		if (timeout_elapsed(timeout_ref))
			break;

	if (io_read32(base + _CRYP_SR) & _CRYP_SR_BUSY)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result wait_end_enable(vaddr_t base)
{
	uint64_t timeout_ref = timeout_init_us(CRYP_TIMEOUT_US);

	while (io_read32(base + _CRYP_CR) & _CRYP_CR_CRYPEN)
		if (timeout_elapsed(timeout_ref))
			break;

	if (io_read32(base + _CRYP_CR) & _CRYP_CR_CRYPEN)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result __must_check write_align_block(struct stm32_cryp_context *ctx,
						 uint32_t *data)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	res = wait_sr_bits(ctx->base, _CRYP_SR_IFNF);
	if (res)
		return res;

	for (i = 0; i < ctx->block_u32; i++) {
		/* No need to htobe() as we configure the HW to swap bytes */
		io_write32(ctx->base + _CRYP_DIN, data[i]);
	}

	return TEE_SUCCESS;
}

static TEE_Result __must_check write_block(struct stm32_cryp_context *ctx,
					   uint8_t *data)
{
	if (!IS_ALIGNED_WITH_TYPE(data, uint32_t)) {
		uint32_t data_u32[MAX_BLOCK_NB_U32] = { 0 };

		memcpy(data_u32, data, ctx->block_u32 * sizeof(uint32_t));
		return write_align_block(ctx, data_u32);
	}

	return write_align_block(ctx, (void *)data);
}

static TEE_Result __must_check read_align_block(struct stm32_cryp_context *ctx,
						uint32_t *data)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	res = wait_sr_bits(ctx->base, _CRYP_SR_OFNE);
	if (res)
		return res;

	for (i = 0; i < ctx->block_u32; i++) {
		/* No need to htobe() as we configure the HW to swap bytes */
		data[i] = io_read32(ctx->base + _CRYP_DOUT);
	}

	return TEE_SUCCESS;
}

static TEE_Result __must_check read_block(struct stm32_cryp_context *ctx,
					  uint8_t *data)
{
	if (!IS_ALIGNED_WITH_TYPE(data, uint32_t)) {
		TEE_Result res = TEE_SUCCESS;
		uint32_t data_u32[MAX_BLOCK_NB_U32] = { 0 };

		res = read_align_block(ctx, data_u32);
		if (res)
			return res;

		memcpy(data, data_u32, ctx->block_u32 * sizeof(uint32_t));

		return TEE_SUCCESS;
	}

	return read_align_block(ctx, (void *)data);
}

static void cryp_end(struct stm32_cryp_context *ctx, TEE_Result prev_error)
{
	if (prev_error) {
		if (rstctrl_assert_to(cryp_pdata.reset, TIMEOUT_US_1MS))
			panic();
		if (rstctrl_deassert_to(cryp_pdata.reset, TIMEOUT_US_1MS))
			panic();
	}

	/* Disable the CRYP peripheral */
	io_clrbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);
}

static void cryp_write_iv(struct stm32_cryp_context *ctx)
{
	if (algo_mode_needs_iv(ctx->cr)) {
		unsigned int i = 0;

		/* Restore the _CRYP_IVRx */
		for (i = 0; i < ctx->block_u32; i++)
			io_write32(ctx->base + _CRYP_IV0LR + i *
				   sizeof(uint32_t), ctx->iv[i]);
	}
}

static void cryp_save_suspend(struct stm32_cryp_context *ctx)
{
	unsigned int i = 0;

	if (IS_ALGOMODE(ctx->cr, AES_GCM) || IS_ALGOMODE(ctx->cr, AES_CCM))
		for (i = 0; i < ARRAY_SIZE(ctx->pm_gcmccm); i++)
			ctx->pm_gcmccm[i] = io_read32(ctx->base +
						      _CRYP_CSGCMCCM0R +
						      i * sizeof(uint32_t));

	if (IS_ALGOMODE(ctx->cr, AES_GCM))
		for (i = 0; i < ARRAY_SIZE(ctx->pm_gcm); i++)
			ctx->pm_gcm[i] = io_read32(ctx->base + _CRYP_CSGCM0R +
						   i * sizeof(uint32_t));
}

static void cryp_restore_suspend(struct stm32_cryp_context *ctx)
{
	unsigned int i = 0;

	if (IS_ALGOMODE(ctx->cr, AES_GCM) || IS_ALGOMODE(ctx->cr, AES_CCM))
		for (i = 0; i < ARRAY_SIZE(ctx->pm_gcmccm); i++)
			io_write32(ctx->base + _CRYP_CSGCMCCM0R +
				   i * sizeof(uint32_t), ctx->pm_gcmccm[i]);

	if (IS_ALGOMODE(ctx->cr, AES_GCM))
		for (i = 0; i < ARRAY_SIZE(ctx->pm_gcm); i++)
			io_write32(ctx->base + _CRYP_CSGCM0R +
				   i * sizeof(uint32_t), ctx->pm_gcm[i]);
}

static void cryp_write_key(struct stm32_cryp_context *ctx)
{
	vaddr_t reg = 0;
	int i = 0;
	uint32_t algo = GET_ALGOMODE(ctx->cr);

	if (algo == _CRYP_CR_ALGOMODE_DES_ECB ||
	    algo == _CRYP_CR_ALGOMODE_DES_CBC)
		reg = ctx->base + _CRYP_K1RR;
	else
		reg = ctx->base + _CRYP_K3RR;

	for (i = ctx->key_size / sizeof(uint32_t) - 1;
	     i >= 0;
	     i--, reg -= sizeof(uint32_t))
		io_write32(reg, ctx->key[i]);
}

static TEE_Result cryp_prepare_key(struct stm32_cryp_context *ctx)
{
	TEE_Result res = TEE_SUCCESS;

	/*
	 * For AES ECB/CBC decryption, key preparation mode must be selected
	 * to populate the key.
	 */
	if (is_decrypt(ctx->cr) && (IS_ALGOMODE(ctx->cr, AES_ECB) ||
				    IS_ALGOMODE(ctx->cr, AES_CBC))) {
		/* Select Algomode "prepare key" */
		io_clrsetbits32(ctx->base + _CRYP_CR, _CRYP_CR_ALGOMODE_MSK,
				_CRYP_CR_ALGOMODE_AES << _CRYP_CR_ALGOMODE_OFF);

		cryp_write_key(ctx);

		/* Enable CRYP */
		io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

		res = wait_end_busy(ctx->base);
		if (res)
			return res;

		/* Reset 'real' algomode */
		io_clrsetbits32(ctx->base + _CRYP_CR, _CRYP_CR_ALGOMODE_MSK,
				ctx->cr & _CRYP_CR_ALGOMODE_MSK);
	} else {
		cryp_write_key(ctx);
	}

	return TEE_SUCCESS;
}

static TEE_Result save_context(struct stm32_cryp_context *ctx)
{
	/* Device should not be in a processing phase */
	if (io_read32(ctx->base + _CRYP_SR) & _CRYP_SR_BUSY)
		return TEE_ERROR_BAD_STATE;

	/* Disable the CRYP peripheral */
	io_clrbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

	/* Save CR */
	ctx->cr = io_read32(ctx->base + _CRYP_CR);

	cryp_save_suspend(ctx);

	/* If algo mode needs to save current IV */
	if (algo_mode_needs_iv(ctx->cr)) {
		unsigned int i = 0;

		/* Save IV */
		for (i = 0; i < ctx->block_u32; i++)
			ctx->iv[i] = io_read32(ctx->base + _CRYP_IV0LR + i *
					       sizeof(uint32_t));
	}

	return TEE_SUCCESS;
}

/* To resume the processing of a message */
static TEE_Result restore_context(struct stm32_cryp_context *ctx)
{
	TEE_Result res = TEE_SUCCESS;

	/* IP should be disabled */
	if (io_read32(ctx->base + _CRYP_CR) & _CRYP_CR_CRYPEN) {
		DMSG("Device is still enabled");
		return TEE_ERROR_BAD_STATE;
	}

	/* Restore the _CRYP_CR */
	io_write32(ctx->base + _CRYP_CR, ctx->cr);

	/* Write key and, in case of AES_CBC or AES_ECB decrypt, prepare it */
	res = cryp_prepare_key(ctx);
	if (res)
		return res;

	cryp_restore_suspend(ctx);

	cryp_write_iv(ctx);

	/* Flush internal fifo */
	io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_FFLUSH);

	/* Enable the CRYP peripheral */
	io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

	return TEE_SUCCESS;
}

/*
 * Translate a byte index in an array of BE uint32_t into the index of same
 * byte in the corresponding LE uint32_t array.
 */
static size_t be_index(size_t index)
{
	return (index & ~0x3) + 3 - (index & 0x3);
}

static TEE_Result ccm_first_context(struct stm32_cryp_context *ctx)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t b0[AES_BLOCK_NB_U32] = { 0 };
	uint8_t *iv = (uint8_t *)ctx->iv;
	size_t l = 0;
	size_t i = 15;

	/* IP should be disabled */
	if (io_read32(ctx->base + _CRYP_CR) & _CRYP_CR_CRYPEN)
		return TEE_ERROR_BAD_STATE;

	/* Write the _CRYP_CR */
	io_write32(ctx->base + _CRYP_CR, ctx->cr);

	/* Write key */
	res = cryp_prepare_key(ctx);
	if (res)
		return res;

	/* Save full IV that will be b0 */
	memcpy(b0, iv, sizeof(b0));

	/*
	 * Update IV to become CTR0/1 before setting it.
	 * IV is saved as LE uint32_t[4] as expected by hardware,
	 * but CCM RFC defines bytes to update in a BE array.
	 */
	/* Set flag bits to 0 (5 higher bits), keep 3 low bits */
	iv[be_index(0)] &= 0x7;
	/* Get size of length field (can be from 2 to 8) */
	l = iv[be_index(0)] + 1;
	/* Set Q to 0 */
	for (i = 15; i >= 15 - l + 1; i--)
		iv[be_index(i)] = 0;
	/* Save CTR0 */
	memcpy(ctx->ctr0_ccm, iv, sizeof(b0));
	/* Increment Q */
	iv[be_index(15)] |= 0x1;

	cryp_write_iv(ctx);

	/* Enable the CRYP peripheral */
	io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

	res = write_align_block(ctx, b0);

	return res;
}

static TEE_Result do_from_init_to_phase(struct stm32_cryp_context *ctx,
					uint32_t new_phase)
{
	TEE_Result res = TEE_SUCCESS;

	/*
	 * We didn't run the init phase yet
	 * CCM need a specific restore_context phase for the init phase
	 */
	if (IS_ALGOMODE(ctx->cr, AES_CCM))
		res = ccm_first_context(ctx);
	else
		res = restore_context(ctx);

	if (res)
		return res;

	res = wait_end_enable(ctx->base);
	if (res)
		return res;

	/* Move to 'new_phase' */
	io_clrsetbits32(ctx->base + _CRYP_CR, _CRYP_CR_GCM_CCMPH_MSK,
			new_phase << _CRYP_CR_GCM_CCMPH_OFF);

	/* Enable the CRYP peripheral (init disabled it) */
	io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

	return TEE_SUCCESS;
}

static TEE_Result do_from_header_to_phase(struct stm32_cryp_context *ctx,
					  uint32_t new_phase)
{
	TEE_Result res = TEE_SUCCESS;

	res = restore_context(ctx);
	if (res)
		return res;

	if (ctx->extra_size) {
		/* Manage unaligned header data before moving to next phase */
		memset((uint8_t *)ctx->extra + ctx->extra_size, 0,
		       ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size);

		res = write_align_block(ctx, ctx->extra);
		if (res)
			return res;

		ctx->assoc_len += (ctx->extra_size) * INT8_BIT;
		ctx->extra_size = 0;
	}

	/* Move to 'new_phase' */
	io_clrsetbits32(ctx->base + _CRYP_CR, _CRYP_CR_GCM_CCMPH_MSK,
			new_phase << _CRYP_CR_GCM_CCMPH_OFF);

	return TEE_SUCCESS;
}

/**
 * @brief Start a AES computation.
 * @param ctx: CRYP process context
 * @param is_dec: true if decryption, false if encryption
 * @param algo: define the algo mode
 * @param key: pointer to key
 * @param key_size: key size
 * @param iv: pointer to initialization vector (unused if algo is ECB)
 * @param iv_size: iv size
 * @note this function doesn't access to hardware but stores in ctx the values
 *
 * @retval TEE_SUCCESS if OK.
 */
TEE_Result stm32_cryp_init(struct stm32_cryp_context *ctx, bool is_dec,
			   enum stm32_cryp_algo_mode algo,
			   const void *key, size_t key_size, const void *iv,
			   size_t iv_size)
{
	unsigned int i = 0;
	const uint32_t *iv_u32 = NULL;
	uint32_t local_iv[4] = { 0 };
	const uint32_t *key_u32 = NULL;
	uint32_t local_key[8] = { 0 };

	ctx->assoc_len = 0;
	ctx->load_len = 0;
	ctx->extra_size = 0;
	ctx->lock = &cryp_lock;

	ctx->base = io_pa_or_va(&cryp_pdata.base, 1);
	ctx->cr = _CRYP_CR_RESET_VALUE;

	/* We want buffer to be u32 aligned */
	if (IS_ALIGNED_WITH_TYPE(key, uint32_t)) {
		key_u32 = key;
	} else {
		memcpy(local_key, key, key_size);
		key_u32 = local_key;
	}

	if (IS_ALIGNED_WITH_TYPE(iv, uint32_t)) {
		iv_u32 = iv;
	} else {
		memcpy(local_iv, iv, iv_size);
		iv_u32 = local_iv;
	}

	if (is_dec)
		SETBITS(ctx->cr, _CRYP_CR_ALGODIR);
	else
		CLRBITS(ctx->cr, _CRYP_CR_ALGODIR);

	/* Save algo mode */
	switch (algo) {
	case STM32_CRYP_MODE_TDES_ECB:
		SET_ALGOMODE(TDES_ECB, ctx->cr);
		break;
	case STM32_CRYP_MODE_TDES_CBC:
		SET_ALGOMODE(TDES_CBC, ctx->cr);
		break;
	case STM32_CRYP_MODE_DES_ECB:
		SET_ALGOMODE(DES_ECB, ctx->cr);
		break;
	case STM32_CRYP_MODE_DES_CBC:
		SET_ALGOMODE(DES_CBC, ctx->cr);
		break;
	case STM32_CRYP_MODE_AES_ECB:
		SET_ALGOMODE(AES_ECB, ctx->cr);
		break;
	case STM32_CRYP_MODE_AES_CBC:
		SET_ALGOMODE(AES_CBC, ctx->cr);
		break;
	case STM32_CRYP_MODE_AES_CTR:
		SET_ALGOMODE(AES_CTR, ctx->cr);
		break;
	case STM32_CRYP_MODE_AES_GCM:
		SET_ALGOMODE(AES_GCM, ctx->cr);
		break;
	case STM32_CRYP_MODE_AES_CCM:
		SET_ALGOMODE(AES_CCM, ctx->cr);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * We will use HW Byte swap (_CRYP_CR_DATATYPE_BYTE) for data.
	 * So we won't need to
	 * TOBE32(data) before write to DIN
	 * nor
	 * FROMBE32 after reading from DOUT.
	 */
	clrsetbits(&ctx->cr, _CRYP_CR_DATATYPE_MSK,
		   _CRYP_CR_DATATYPE_BYTE << _CRYP_CR_DATATYPE_OFF);

	/*
	 * Configure keysize for AES algorithms
	 * And save block size
	 */
	if (algo_mode_is_aes(ctx->cr)) {
		switch (key_size) {
		case AES_KEYSIZE_128:
			clrsetbits(&ctx->cr, _CRYP_CR_KEYSIZE_MSK,
				   _CRYP_CR_KSIZE_128 << _CRYP_CR_KEYSIZE_OFF);
			break;
		case AES_KEYSIZE_192:
			clrsetbits(&ctx->cr, _CRYP_CR_KEYSIZE_MSK,
				   _CRYP_CR_KSIZE_192 << _CRYP_CR_KEYSIZE_OFF);
			break;
		case AES_KEYSIZE_256:
			clrsetbits(&ctx->cr, _CRYP_CR_KEYSIZE_MSK,
				   _CRYP_CR_KSIZE_256 << _CRYP_CR_KEYSIZE_OFF);
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}

		/* And set block size */
		ctx->block_u32 = AES_BLOCK_NB_U32;
	} else {
		/* And set DES/TDES block size */
		ctx->block_u32 = DES_BLOCK_NB_U32;
	}

	/* Save key in HW order */
	ctx->key_size = key_size;
	for (i = 0; i < key_size / sizeof(uint32_t); i++)
		ctx->key[i] = TOBE32(key_u32[i]);

	/* Save IV */
	if (algo_mode_needs_iv(ctx->cr)) {
		if (!iv || iv_size != ctx->block_u32 * sizeof(uint32_t))
			return TEE_ERROR_BAD_PARAMETERS;

		/*
		 * We save IV in the byte order expected by the
		 * IV registers
		 */
		for (i = 0; i < ctx->block_u32; i++)
			ctx->iv[i] = TOBE32(iv_u32[i]);
	}

	/* Reset suspend registers */
	memset(ctx->pm_gcmccm, 0, sizeof(ctx->pm_gcmccm));
	memset(ctx->pm_gcm, 0, sizeof(ctx->pm_gcm));

	return TEE_SUCCESS;
}

/**
 * @brief Update (or start) a AES authenticate process of
 *        associated data (CCM or GCM).
 * @param ctx: CRYP process context
 * @param data: pointer to associated data
 * @param data_size: data size
 * @retval TEE_SUCCESS if OK.
 */
TEE_Result stm32_cryp_update_assodata(struct stm32_cryp_context *ctx,
				      uint8_t *data, size_t data_size)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;
	uint32_t previous_phase = 0;

	/* If no associated data, nothing to do */
	if (!data || !data_size)
		return TEE_SUCCESS;

	mutex_lock(ctx->lock);

	previous_phase = (ctx->cr & _CRYP_CR_GCM_CCMPH_MSK) >>
			 _CRYP_CR_GCM_CCMPH_OFF;

	switch (previous_phase) {
	case _CRYP_CR_GCM_CCMPH_INIT:
		res = do_from_init_to_phase(ctx, _CRYP_CR_GCM_CCMPH_HEADER);
		break;
	case _CRYP_CR_GCM_CCMPH_HEADER:
		/*
		 * Function update_assodata was already called.
		 * We only need to restore the context.
		 */
		res = restore_context(ctx);
		break;
	default:
		assert(0);
		res = TEE_ERROR_BAD_STATE;
	}

	if (res)
		goto out;

	/* Manage if remaining data from a previous update_assodata call */
	if (ctx->extra_size &&
	    (ctx->extra_size + data_size >=
	     ctx->block_u32 * sizeof(uint32_t))) {
		uint32_t block[MAX_BLOCK_NB_U32] = { 0 };

		memcpy(block, ctx->extra, ctx->extra_size);
		memcpy((uint8_t *)block + ctx->extra_size, data,
		       ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size);

		res = write_align_block(ctx, block);
		if (res)
			goto out;

		i += ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size;
		ctx->extra_size = 0;
		ctx->assoc_len += ctx->block_u32 * sizeof(uint32_t) * INT8_BIT;
	}

	while (data_size - i >= ctx->block_u32 * sizeof(uint32_t)) {
		res = write_block(ctx, data + i);
		if (res)
			goto out;

		/* Process next block */
		i += ctx->block_u32 * sizeof(uint32_t);
		ctx->assoc_len += ctx->block_u32 * sizeof(uint32_t) * INT8_BIT;
	}

	/*
	 * Manage last block if not a block size multiple:
	 * Save remaining data to manage them later (potentially with new
	 * associated data).
	 */
	if (i < data_size) {
		memcpy((uint8_t *)ctx->extra + ctx->extra_size, data + i,
		       data_size - i);
		ctx->extra_size += data_size - i;
	}

	res = save_context(ctx);
out:
	if (res)
		cryp_end(ctx, res);

	mutex_unlock(ctx->lock);

	return res;
}

/**
 * @brief Update (or start) a AES authenticate and de/encrypt with
 *        payload data (CCM or GCM).
 * @param ctx: CRYP process context
 * @param data_in: pointer to payload
 * @param data_out: pointer where to save de/encrypted payload
 * @param data_size: payload size
 *
 * @retval TEE_SUCCESS if OK.
 */
TEE_Result stm32_cryp_update_load(struct stm32_cryp_context *ctx,
				  uint8_t *data_in, uint8_t *data_out,
				  size_t data_size)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;
	uint32_t previous_phase = 0;

	if (!data_in || !data_size)
		return TEE_SUCCESS;

	mutex_lock(ctx->lock);

	previous_phase = (ctx->cr & _CRYP_CR_GCM_CCMPH_MSK) >>
			 _CRYP_CR_GCM_CCMPH_OFF;

	switch (previous_phase) {
	case _CRYP_CR_GCM_CCMPH_INIT:
		res = do_from_init_to_phase(ctx, _CRYP_CR_GCM_CCMPH_PAYLOAD);
		break;
	case _CRYP_CR_GCM_CCMPH_HEADER:
		res = do_from_header_to_phase(ctx, _CRYP_CR_GCM_CCMPH_PAYLOAD);
		break;
	case _CRYP_CR_GCM_CCMPH_PAYLOAD:
		/* new update_load call, we only need to restore context */
		res = restore_context(ctx);
		break;
	default:
		assert(0);
		res = TEE_ERROR_BAD_STATE;
	}

	if (res)
		goto out;

	/* Manage if incomplete block from a previous update_load call */
	if (ctx->extra_size &&
	    (ctx->extra_size + data_size >=
	     ctx->block_u32 * sizeof(uint32_t))) {
		uint32_t block_out[MAX_BLOCK_NB_U32] = { 0 };

		memcpy((uint8_t *)ctx->extra + ctx->extra_size, data_in + i,
		       ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size);

		res = write_align_block(ctx, ctx->extra);
		if (res)
			goto out;

		res = read_align_block(ctx, block_out);
		if (res)
			goto out;

		memcpy(data_out + i, (uint8_t *)block_out + ctx->extra_size,
		       ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size);

		i += ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size;
		ctx->extra_size = 0;

		ctx->load_len += ctx->block_u32 * sizeof(uint32_t) * INT8_BIT;
	}

	while (data_size - i >= ctx->block_u32 * sizeof(uint32_t)) {
		res = write_block(ctx, data_in + i);
		if (res)
			goto out;

		res = read_block(ctx, data_out + i);
		if (res)
			goto out;

		/* Process next block */
		i += ctx->block_u32 * sizeof(uint32_t);
		ctx->load_len += ctx->block_u32 * sizeof(uint32_t) * INT8_BIT;
	}

	res = save_context(ctx);
	if (res)
		goto out;

	/*
	 * Manage last block if not a block size multiple
	 * We saved context,
	 * Complete block with 0 and send to CRYP to get {en,de}crypted data
	 * Store data to resend as last block in final()
	 * or to complete next update_load() to get correct tag.
	 */
	if (i < data_size) {
		uint32_t block_out[MAX_BLOCK_NB_U32] = { 0 };
		size_t prev_extra_size = ctx->extra_size;

		/* Re-enable the CRYP peripheral */
		io_setbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);

		memcpy((uint8_t *)ctx->extra + ctx->extra_size, data_in + i,
		       data_size - i);
		ctx->extra_size += data_size - i;
		memset((uint8_t *)ctx->extra + ctx->extra_size, 0,
		       ctx->block_u32 * sizeof(uint32_t) - ctx->extra_size);

		res = write_align_block(ctx, ctx->extra);
		if (res)
			goto out;

		res = read_align_block(ctx, block_out);
		if (res)
			goto out;

		memcpy(data_out + i, (uint8_t *)block_out + prev_extra_size,
		       data_size - i);

		/* Disable the CRYP peripheral */
		io_clrbits32(ctx->base + _CRYP_CR, _CRYP_CR_CRYPEN);
	}

out:
	if (res)
		cryp_end(ctx, res);

	mutex_unlock(ctx->lock);

	return res;
}

/**
 * @brief Get authentication tag for AES authenticated algorithms (CCM or GCM).
 * @param ctx: CRYP process context
 * @param tag: pointer where to save the tag
 * @param data_size: tag size
 *
 * @retval TEE_SUCCESS if OK.
 */
TEE_Result stm32_cryp_final(struct stm32_cryp_context *ctx, uint8_t *tag,
			    size_t tag_size)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t tag_u32[4] = { 0 };
	uint32_t previous_phase = 0;

	mutex_lock(ctx->lock);

	previous_phase = (ctx->cr & _CRYP_CR_GCM_CCMPH_MSK) >>
			 _CRYP_CR_GCM_CCMPH_OFF;

	switch (previous_phase) {
	case _CRYP_CR_GCM_CCMPH_INIT:
		res = do_from_init_to_phase(ctx, _CRYP_CR_GCM_CCMPH_FINAL);
		break;
	case _CRYP_CR_GCM_CCMPH_HEADER:
		res = do_from_header_to_phase(ctx, _CRYP_CR_GCM_CCMPH_FINAL);
		break;
	case _CRYP_CR_GCM_CCMPH_PAYLOAD:
		res = restore_context(ctx);
		if (res)
			break;

		/* Manage if incomplete block from a previous update_load() */
		if (ctx->extra_size) {
			uint32_t block_out[MAX_BLOCK_NB_U32] = { 0 };
			size_t sz = ctx->block_u32 * sizeof(uint32_t) -
				    ctx->extra_size;

			if (does_need_npblb(ctx->cr)) {
				io_clrsetbits32(ctx->base + _CRYP_CR,
						_CRYP_CR_NPBLB_MSK,
						sz << _CRYP_CR_NPBLB_OFF);
			}

			memset((uint8_t *)ctx->extra + ctx->extra_size, 0, sz);

			res = write_align_block(ctx, ctx->extra);
			if (res)
				break;

			/* Don't care {en,de}crypted data, already saved */
			res = read_align_block(ctx, block_out);
			if (res)
				break;

			ctx->load_len += (ctx->extra_size * INT8_BIT);
			ctx->extra_size = 0;
		}

		/* Move to final phase */
		io_clrsetbits32(ctx->base + _CRYP_CR, _CRYP_CR_GCM_CCMPH_MSK,
				_CRYP_CR_GCM_CCMPH_FINAL <<
				_CRYP_CR_GCM_CCMPH_OFF);
		break;
	default:
		assert(0);
		res = TEE_ERROR_BAD_STATE;
	}

	if (res)
		goto out;

	if (IS_ALGOMODE(ctx->cr, AES_GCM)) {
		/* No need to htobe() as we configure the HW to swap bytes */
		io_write32(ctx->base + _CRYP_DIN, 0U);
		io_write32(ctx->base + _CRYP_DIN, ctx->assoc_len);
		io_write32(ctx->base + _CRYP_DIN, 0U);
		io_write32(ctx->base + _CRYP_DIN, ctx->load_len);
	} else if (IS_ALGOMODE(ctx->cr, AES_CCM)) {
		/* No need to htobe() in this phase */
		res = write_align_block(ctx, ctx->ctr0_ccm);
		if (res)
			goto out;
	}

	res = read_align_block(ctx, tag_u32);
	if (res)
		goto out;

	memcpy(tag, tag_u32, MIN(sizeof(tag_u32), tag_size));

out:
	cryp_end(ctx, res);
	mutex_unlock(ctx->lock);

	return res;
}

/**
 * @brief Update (or start) a de/encrypt process.
 * @param ctx: CRYP process context
 * @param last_block: true if last payload data block
 * @param data_in: pointer to payload
 * @param data_out: pointer where to save de/encrypted payload
 * @param data_size: payload size
 *
 * @retval TEE_SUCCESS if OK.
 */
TEE_Result stm32_cryp_update(struct stm32_cryp_context *ctx, bool last_block,
			     uint8_t *data_in, uint8_t *data_out,
			     size_t data_size)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	mutex_lock(ctx->lock);

	/*
	 * In CBC and ECB encryption we need to manage specifically last
	 * 2 blocks if total size in not aligned to a block size.
	 * Currently return TEE_ERROR_NOT_IMPLEMENTED. Moreover as we need to
	 * know last 2 blocks, if unaligned and call with less than two blocks,
	 * return TEE_ERROR_BAD_STATE.
	 */
	if (last_block && algo_mode_is_ecb_cbc(ctx->cr) &&
	    is_encrypt(ctx->cr) &&
	    (ROUNDDOWN(data_size, ctx->block_u32 * sizeof(uint32_t)) !=
	     data_size)) {
		if (data_size < ctx->block_u32 * sizeof(uint32_t) * 2) {
			/*
			 * If CBC, size of the last part should be at
			 * least 2*BLOCK_SIZE
			 */
			EMSG("Unexpected last block size");
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}
		/*
		 * Moreover the ECB/CBC specific padding for encrypt is not
		 * yet implemented, and not used in OPTEE
		 */
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	/* Manage remaining CTR mask from previous update call */
	if (IS_ALGOMODE(ctx->cr, AES_CTR) && ctx->extra_size) {
		unsigned int j = 0;
		uint8_t *mask = (uint8_t *)ctx->extra;

		for (j = 0; j < ctx->extra_size && i < data_size; j++, i++)
			data_out[i] = data_in[i] ^ mask[j];

		if (j != ctx->extra_size) {
			/*
			 * We didn't consume all saved mask,
			 * but no more data.
			 */

			/* We save remaining mask and its new size */
			memmove(ctx->extra, ctx->extra + j,
				ctx->extra_size - j);
			ctx->extra_size -= j;

			/*
			 * We don't need to save HW context we didn't
			 * modify HW state.
			 */
			res = TEE_SUCCESS;
			goto out;
		}

		/* All extra mask consumed */
		ctx->extra_size = 0;
	}

	res = restore_context(ctx);
	if (res)
		goto out;

	while (data_size - i >= ctx->block_u32 * sizeof(uint32_t)) {
		/*
		 * We only write/read one block at a time
		 * but CRYP use a in (and out) FIFO of 8 * uint32_t
		 */
		res = write_block(ctx, data_in + i);
		if (res)
			goto out;

		res = read_block(ctx, data_out + i);
		if (res)
			goto out;

		/* Process next block */
		i += ctx->block_u32 * sizeof(uint32_t);
	}

	/* Manage last block if not a block size multiple */
	if (i < data_size) {
		uint32_t block_in[MAX_BLOCK_NB_U32] = { 0 };
		uint32_t block_out[MAX_BLOCK_NB_U32] = { 0 };

		if (!IS_ALGOMODE(ctx->cr, AES_CTR)) {
			/*
			 * Other algorithm than CTR can manage only multiple
			 * of block_size.
			 */
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		/*
		 * For CTR we save the generated mask to use it at next
		 * update call.
		 */
		memcpy(block_in, data_in + i, data_size - i);

		res = write_align_block(ctx, block_in);
		if (res)
			goto out;

		res = read_align_block(ctx, block_out);
		if (res)
			goto out;

		memcpy(data_out + i, block_out, data_size - i);

		/* Save mask for possibly next call */
		ctx->extra_size = ctx->block_u32 * sizeof(uint32_t) -
			(data_size - i);
		memcpy(ctx->extra, (uint8_t *)block_out + data_size - i,
		       ctx->extra_size);
	}

	if (!last_block)
		res = save_context(ctx);

out:
	/* If last block or error, end of CRYP process */
	if (last_block || res)
		cryp_end(ctx, res);

	mutex_unlock(ctx->lock);

	return res;
}

static TEE_Result stm32_cryp_probe(const void *fdt, int node,
				   const void *compt_data __unused)
{
	TEE_Result res = TEE_SUCCESS;
	struct dt_node_info dt_cryp = { };
	struct rstctrl *rstctrl = NULL;
	struct clk *clk = NULL;

	_fdt_fill_device_info(fdt, &dt_cryp, node);

	if (dt_cryp.reg == DT_INFO_INVALID_REG ||
	    dt_cryp.reg_size == DT_INFO_INVALID_REG_SIZE)
		panic();

	res = clk_dt_get_by_index(fdt, node, 0, &clk);
	if (res)
		return res;

	res = rstctrl_dt_get_by_index(fdt, node, 0, &rstctrl);
	if (res)
		return res;

	cryp_pdata.clock = clk;
	cryp_pdata.reset = rstctrl;
	cryp_pdata.base.pa = dt_cryp.reg;

	io_pa_or_va_secure(&cryp_pdata.base, dt_cryp.reg_size);
	if (!cryp_pdata.base.va)
		panic();

	stm32mp_register_secure_periph_iomem(cryp_pdata.base.pa);

	if (clk_enable(cryp_pdata.clock))
		panic();

	if (rstctrl_assert_to(cryp_pdata.reset, TIMEOUT_US_1MS))
		panic();

	if (rstctrl_deassert_to(cryp_pdata.reset, TIMEOUT_US_1MS))
		panic();

	if (IS_ENABLED(CFG_CRYPTO_DRV_AUTHENC)) {
		res = stm32_register_authenc();
		if (res) {
			EMSG("Failed to register to authenc: %#"PRIx32, res);
			panic();
		}
	}

	if (IS_ENABLED(CFG_CRYPTO_DRV_CIPHER)) {
		res = stm32_register_cipher();
		if (res) {
			EMSG("Failed to register to cipher: %#"PRIx32, res);
			panic();
		}
	}

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_cryp_match_table[] = {
	{ .compatible = "st,stm32mp1-cryp" },
	{ }
};

DEFINE_DT_DRIVER(stm32_cryp_dt_driver) = {
	.name = "stm32-cryp",
	.match_table = stm32_cryp_match_table,
	.probe = stm32_cryp_probe,
};
