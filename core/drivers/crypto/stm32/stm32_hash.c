// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2025, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <config.h>
#include <drivers/clk_dt.h>
#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/mutex.h>
#include <libfdt.h>
#include <stm32_util.h>
#include <utee_defines.h>
#include <util.h>

#include "common.h"
#include "stm32_hash.h"

#define _HASH_CR			U(0x00)
#define _HASH_DIN			U(0x04)
#define _HASH_STR			U(0x08)
#define _HASH_IMR			U(0x20)
#define _HASH_SR			U(0x24)
#define _HASH_HR(x)			(U(0x310) + ((x) * U(0x04)))
#define _HASH_VERR			U(0x3F4)
#define _HASH_CSR(x)			(U(0xF8) + ((x) * U(0x04)))

/* Control Register */
#define _HASH_CR_INIT			BIT(2)
#define _HASH_CR_MODE			BIT(6)
#define _HASH_CR_DATATYPE_SHIFT		U(4)
#define _HASH_CR_DATATYPE_NONE		SHIFT_U32(U(0), _HASH_CR_DATATYPE_SHIFT)
#define _HASH_CR_DATATYPE_HALFWORD	SHIFT_U32(U(1), _HASH_CR_DATATYPE_SHIFT)
#define _HASH_CR_DATATYPE_BYTE		SHIFT_U32(U(2), _HASH_CR_DATATYPE_SHIFT)
#define _HASH_CR_DATATYPE_BIT		SHIFT_U32(U(3), _HASH_CR_DATATYPE_SHIFT)
#define _HASH_CR_LKEY			BIT(16)

#define _HASH_CR_ALGO_SHIFT		U(17)
#define _HASH_CR_ALGO_MD5		BIT(7)
#define _HASH_CR_ALGO_SHA1		SHIFT_U32(U(0x0), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA224		SHIFT_U32(U(0x2), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA256		SHIFT_U32(U(0x3), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA256_IF_MD5	(BIT(18) | BIT(7))
#define _HASH_CR_ALGO_SHA384		SHIFT_U32(U(0xC), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA512_224	SHIFT_U32(U(0xD), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA512_256	SHIFT_U32(U(0xE), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA512		SHIFT_U32(U(0xF), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA3_224		SHIFT_U32(U(0x4), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA3_256		SHIFT_U32(U(0x5), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA3_384		SHIFT_U32(U(0x6), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHA3_512		SHIFT_U32(U(0x7), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHAKE128		SHIFT_U32(U(0x8), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_SHAKE256		SHIFT_U32(U(0x9), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_RAWSHAKE128	SHIFT_U32(U(0xA), _HASH_CR_ALGO_SHIFT)
#define _HASH_CR_ALGO_RAWSHAKE256	SHIFT_U32(U(0xB), _HASH_CR_ALGO_SHIFT)

/* Status Flags */
#define _HASH_SR_DINIS			BIT(0)
#define _HASH_SR_DCIS			BIT(1)
#define _HASH_SR_BUSY			BIT(3)
#define _HASH_SR_NBWP_MASK		GENMASK_32(13, 9)
#define _HASH_SR_NBWP_OFF		9
#define _HASH_SR_NBWE_MASK		GENMASK_32(21, 16)
#define _HASH_SR_NBWE_OFF		16

/* STR Register */
#define _HASH_STR_NBLW_MASK		GENMASK_32(4, 0)
#define _HASH_STR_DCAL			BIT(8)

/* _iHASH_VERR bit fields */
#define _HASH_VERR_MINREV		GENMASK_32(3, 0)
#define _HASH_VERR_MAJREV		GENMASK_32(7, 4)

/* Digest size in nb of uint32_t */
#define MD5_DIGEST_U32			U(4)
#define SHA1_DIGEST_U32			U(5)
#define SHA224_DIGEST_U32		U(7)
#define SHA256_DIGEST_U32		U(8)
#define SHA384_DIGEST_U32		U(12)
#define SHA512_224_DIGEST_U32		U(7)
#define SHA512_256_DIGEST_U32		U(8)
#define SHA512_DIGEST_U32		U(16)
#define SHA3_224_DIGEST_U32		U(7)
#define SHA3_256_DIGEST_U32		U(8)
#define SHA3_384_DIGEST_U32		U(12)
#define SHA3_512_DIGEST_U32		U(16)

/* Internal block size */
#define MD5_BLOCK_SIZE			U(64)
#define SHA1_BLOCK_SIZE			U(64)
#define SHA224_BLOCK_SIZE		U(64)
#define SHA256_BLOCK_SIZE		U(64)
#define SHA384_BLOCK_SIZE		U(128)
#define SHA512_224_BLOCK_SIZE		U(128)
#define SHA512_256_BLOCK_SIZE		U(128)
#define SHA512_BLOCK_SIZE		U(128)
#define SHA3_224_BLOCK_SIZE		U(144)
#define SHA3_256_BLOCK_SIZE		U(136)
#define SHA3_384_BLOCK_SIZE		U(104)
#define SHA3_512_BLOCK_SIZE		U(72)

/* Define the registers needed to save context */
#define SAVE_SMALL			U(1)
#define SAVE_BIG			U(2)
#define SAVE_SHA3			U(3)

#define SAVE_SMALL_NB_REG		U(22)
#define SAVE_SMALL_FIRST_REG		U(0)
#define SAVE_SMALL_HMAC_NB_REG		U(16)
#define SAVE_SMALL_HMAC_FIRST_REG	U(38)
#define SAVE_BIG_NB_REG			U(91)
#define SAVE_BIG_FIRST_REG		U(0)
#define SAVE_BIG_HMAC_NB_REG		U(12)
#define SAVE_BIG_HMAC_FIRST_REG		U(91)
#define SAVE_SHA3_NB_REG		U(72)
#define SAVE_SHA3_FIRST_REG		U(0)
#define SAVE_SHA3_HMAC_NB_REG		U(72)
#define SAVE_SHA3_HMAC_FIRST_REG	U(16)

#define RESET_TIMEOUT_US_1MS		U(1000)
#define HASH_TIMEOUT_US			U(10000)

/* Define capabilities */
#define CAPS_MD5			BIT(0)
#define CAPS_SHA1			BIT(1)
#define CAPS_SHA2_224			BIT(2)
#define CAPS_SHA2_256			BIT(3)
#define CAPS_SHA2_384			BIT(4)
#define CAPS_SHA2_512			BIT(5)
#define CAPS_SHA3			BIT(6)

struct stm32_hash_compat {
	uint32_t caps;
};

struct stm32_hash_platdata {
	vaddr_t base;
	struct clk *clock;
	struct rstctrl *reset;
	struct stm32_hash_compat *compat;
};

struct stm32_hash_device {
	struct stm32_hash_platdata pdata;
	struct mutex lock; /* Protect HASH HW instance access */
};

static struct stm32_hash_device *stm32_hash;

static TEE_Result wait_end_busy(vaddr_t base)
{
	uint32_t value = 0;
	uint32_t addr = base + _HASH_SR;

	/* Timeout may append due to a schedule after the while(timeout()) */
	if (IO_READ32_POLL_TIMEOUT(addr, value, !(value & _HASH_SR_BUSY), 0,
				   HASH_TIMEOUT_US)) {
		EMSG("Busy timeout");
		return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

static int wait_digest_ready(vaddr_t base)
{
	uint32_t value = 0;
	uint32_t addr = base + _HASH_SR;

	/* Timeout may append due to a schedule after the while(test) */
	if (IO_READ32_POLL_TIMEOUT(addr, value, value & _HASH_SR_DCIS, 0,
				   HASH_TIMEOUT_US)) {
		EMSG("Ready timeout");
		return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

static TEE_Result hash_write_data(vaddr_t base, uint32_t data)
{
	io_write32(base + _HASH_DIN, data);

	return wait_end_busy(base);
}

static TEE_Result write_key(vaddr_t base, const uint8_t *key, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tmp_buf = 0;

	io_clrsetbits32(base + _HASH_STR, _HASH_STR_NBLW_MASK,
			8 * (len % sizeof(uint32_t)));

	while (len / sizeof(uint32_t)) {
		memcpy(&tmp_buf, key, sizeof(uint32_t));
		res = hash_write_data(base, tmp_buf);
		if (res)
			return res;

		key += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	if (len) {
		tmp_buf = 0;
		memcpy(&tmp_buf, key, len);
		res = hash_write_data(base, tmp_buf);
		if (res)
			return res;
	}

	io_setbits32(base + _HASH_STR, _HASH_STR_DCAL);

	return TEE_SUCCESS;
}

static void get_save_registers(struct stm32_hash_context *c, size_t *nb_regs,
			       size_t *first, size_t *hmac_nb_regs,
			       size_t *hmac_first)
{
	switch (c->save_mode) {
	case SAVE_SMALL:
		*nb_regs = SAVE_SMALL_NB_REG;
		*first = SAVE_SMALL_FIRST_REG;
		if (c->mode == STM32_HMAC_MODE) {
			*hmac_nb_regs = SAVE_SMALL_HMAC_NB_REG;
			*hmac_first = SAVE_SMALL_HMAC_FIRST_REG;
		}
		break;

	case SAVE_BIG:
		*nb_regs = SAVE_BIG_NB_REG;
		*first = SAVE_BIG_FIRST_REG;
		if (c->mode == STM32_HMAC_MODE) {
			*hmac_nb_regs = SAVE_BIG_HMAC_NB_REG;
			*hmac_first = SAVE_BIG_HMAC_FIRST_REG;
		}
		break;

	case SAVE_SHA3:
		*nb_regs = SAVE_SHA3_NB_REG;
		*first = SAVE_SHA3_FIRST_REG;
		if (c->mode == STM32_HMAC_MODE) {
			*hmac_nb_regs = SAVE_SHA3_HMAC_NB_REG;
			*hmac_first = SAVE_SHA3_HMAC_FIRST_REG;
		}
		break;

	default:
		break;
	}
}

static TEE_Result save_context(struct stm32_hash_context *c)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;
	size_t nb_reg = 0;
	size_t first = 0;
	size_t hmac_nb_reg = 0;
	size_t hmac_first = 0;
	vaddr_t base = c->dev->pdata.base;

	res = wait_end_busy(base);
	if (res)
		return res;

	/* Check that FIFO is empty */
	if (!(io_read32(base + _HASH_SR) & _HASH_SR_DINIS))
		return TEE_ERROR_BAD_STATE;

	c->imr = io_read32(base + _HASH_IMR);
	c->str = io_read32(base + _HASH_STR);
	c->cr = io_read32(base + _HASH_CR);

	get_save_registers(c, &nb_reg, &first, &hmac_nb_reg, &hmac_first);

	if (!c->csr)
		return TEE_ERROR_BAD_STATE;

	/* Save context registers */
	for (i = 0; i < nb_reg; i++)
		c->csr[i] = io_read32(base + _HASH_CSR(i + first));
	/* Save HMAC context registers */
	for (i = 0 ; i < hmac_nb_reg; i++)
		c->csr[i + nb_reg] = io_read32(base + _HASH_CSR(i +
								hmac_first));

	return TEE_SUCCESS;
}

static TEE_Result restore_context(struct stm32_hash_context *c)
{
	size_t i = 0;
	size_t nb_reg = 0;
	size_t first = 0;
	size_t hmac_nb_reg = 0;
	size_t hmac_first = 0;
	vaddr_t base = c->dev->pdata.base;

	io_write32(base + _HASH_IMR, c->imr);
	io_write32(base + _HASH_STR, c->str);
	io_write32(base + _HASH_CR, c->cr | _HASH_CR_INIT);

	get_save_registers(c, &nb_reg, &first, &hmac_nb_reg, &hmac_first);

	if (!c->csr)
		return TEE_ERROR_BAD_STATE;

	/* Restore context registers */
	for (i = 0; i < nb_reg; i++)
		io_write32(base + _HASH_CSR(i + first), c->csr[i]);

	/* Restore HMAC context registers */
	for (i = 0 ; i < hmac_nb_reg; i++)
		io_write32(base + _HASH_CSR(i + hmac_first),
			   c->csr[i + nb_reg]);

	return TEE_SUCCESS;
}

static TEE_Result hw_init(struct stm32_hash_context *c, const uint8_t *key,
			  size_t len)
{
	uint32_t reg_cr = 0;
	vaddr_t base = c->dev->pdata.base;

	reg_cr = _HASH_CR_INIT | _HASH_CR_DATATYPE_BYTE;

	switch (c->algo) {
	case STM32_HASH_MD5:
		reg_cr |= _HASH_CR_ALGO_MD5;
		break;
	case STM32_HASH_SHA1:
		reg_cr |= _HASH_CR_ALGO_SHA1;
		break;
	case STM32_HASH_SHA224:
		reg_cr |= _HASH_CR_ALGO_SHA224;
		break;
	case STM32_HASH_SHA384:
		reg_cr |= _HASH_CR_ALGO_SHA384;
		break;
	case STM32_HASH_SHA512:
		reg_cr |= _HASH_CR_ALGO_SHA512;
		break;
	case STM32_HASH_SHA3_224:
		reg_cr |= _HASH_CR_ALGO_SHA3_224;
		break;
	case STM32_HASH_SHA3_256:
		reg_cr |= _HASH_CR_ALGO_SHA3_256;
		break;
	case STM32_HASH_SHA3_384:
		reg_cr |= _HASH_CR_ALGO_SHA3_384;
		break;
	case STM32_HASH_SHA3_512:
		reg_cr |= _HASH_CR_ALGO_SHA3_512;
		break;
	/* Default selected algo is SHA256 */
	case STM32_HASH_SHA256:
		if (c->dev->pdata.compat->caps & CAPS_MD5)
			reg_cr |= _HASH_CR_ALGO_SHA256_IF_MD5;
		else
			reg_cr |= _HASH_CR_ALGO_SHA256;

		break;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	if (c->mode == STM32_HMAC_MODE) {
		reg_cr |= _HASH_CR_MODE;

		if (len > c->block_size)
			reg_cr |= _HASH_CR_LKEY;

		io_write32(base + _HASH_CR, reg_cr);

		return write_key(base, key, len);
	}

	io_write32(base + _HASH_CR, reg_cr);

	return TEE_SUCCESS;
}

static TEE_Result hash_get_digest(struct stm32_hash_context *c, uint8_t *digest)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = c->dev->pdata.base;
	uint32_t i = 0;
	uint32_t dsg = 0;

	res = wait_digest_ready(base);
	if (res)
		return res;

	for (i = 0; i < c->digest_u32; i++) {
		dsg = TEE_U32_FROM_BIG_ENDIAN(io_read32(base + _HASH_HR(i)));
		memcpy(digest + (i * sizeof(uint32_t)), &dsg, sizeof(uint32_t));
	}

	return TEE_SUCCESS;
}

size_t stm32_hash_digest_size(struct stm32_hash_context *c)
{
	assert(c);

	return c->digest_u32 * sizeof(uint32_t);
}

TEE_Result stm32_hash_deep_copy(struct stm32_hash_context *dst,
				struct stm32_hash_context *src)
{
	size_t nb_reg = 0;
	size_t first = 0;
	size_t hmac_nb_reg = 0;
	size_t hmac_first = 0;
	uint32_t *dst_buf = NULL;
	uint32_t *dst_csr = NULL;

	if (!dst || !src || dst->mode != src->mode || dst->algo != src->algo)
		return TEE_ERROR_BAD_PARAMETERS;

	dst_buf = dst->remain.buf;
	dst_csr = dst->csr;
	*dst = *src;
	dst->remain.buf = dst_buf;
	dst->csr = dst_csr;

	memcpy(dst->remain.buf, src->remain.buf, dst->remain.len);
	get_save_registers(dst, &nb_reg, &first, &hmac_nb_reg, &hmac_first);
	memcpy(dst->csr, src->csr, (nb_reg + hmac_nb_reg) * sizeof(uint32_t));

	return TEE_SUCCESS;
}

TEE_Result stm32_hash_alloc(struct stm32_hash_context *c,
			    enum stm32_hash_mode mode,
			    enum stm32_hash_algo algo)
{
	size_t nb_reg = 0;
	size_t first = 0;
	size_t hmac_nb_reg = 0;
	size_t hmac_first = 0;

	assert(c);

	/* Check if initialized */
	if (!stm32_hash)
		return TEE_ERROR_NOT_IMPLEMENTED;

	c->dev = stm32_hash;
	c->mode = mode;
	c->algo = algo;

	switch (algo) {
	case STM32_HASH_MD5:
		if (!(c->dev->pdata.compat->caps & CAPS_MD5))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = MD5_DIGEST_U32;
		c->block_size = MD5_BLOCK_SIZE;
		c->save_mode = SAVE_SMALL;
		break;
	case STM32_HASH_SHA1:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA1))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA1_DIGEST_U32;
		c->block_size = SHA1_BLOCK_SIZE;
		c->save_mode = SAVE_SMALL;
		break;
	case STM32_HASH_SHA224:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA2_224))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA224_DIGEST_U32;
		c->block_size = SHA224_BLOCK_SIZE;
		c->save_mode = SAVE_SMALL;
		break;
	case STM32_HASH_SHA256:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA2_256))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA256_DIGEST_U32;
		c->block_size = SHA256_BLOCK_SIZE;
		c->save_mode = SAVE_SMALL;
		break;
	case STM32_HASH_SHA384:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA2_384))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA384_DIGEST_U32;
		c->block_size = SHA384_BLOCK_SIZE;
		c->save_mode = SAVE_BIG;
		break;
	case STM32_HASH_SHA512:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA2_512))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA512_DIGEST_U32;
		c->block_size = SHA512_BLOCK_SIZE;
		c->save_mode = SAVE_BIG;
		break;
	case STM32_HASH_SHA3_224:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA3))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA3_224_DIGEST_U32;
		c->block_size = SHA3_224_BLOCK_SIZE;
		c->save_mode = SAVE_SHA3;
		break;
	case STM32_HASH_SHA3_256:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA3))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA3_256_DIGEST_U32;
		c->block_size = SHA3_256_BLOCK_SIZE;
		c->save_mode = SAVE_SHA3;
		break;
	case STM32_HASH_SHA3_384:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA3))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA3_384_DIGEST_U32;
		c->block_size = SHA3_384_BLOCK_SIZE;
		c->save_mode = SAVE_SHA3;
		break;
	case STM32_HASH_SHA3_512:
		if (!(c->dev->pdata.compat->caps & CAPS_SHA3))
			return TEE_ERROR_NOT_IMPLEMENTED;

		c->digest_u32 = SHA3_512_DIGEST_U32;
		c->block_size = SHA3_512_BLOCK_SIZE;
		c->save_mode = SAVE_SHA3;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	/*
	 * The queue size is block_size + one register at first
	 * then block_size.
	 * So we may need to save at max queue_size + 3 bytes.
	 * Let allocate a number of uin32_t: queue_size + 4.
	 */
	c->remain.buf = calloc(c->block_size + sizeof(uint32_t), 1);
	if (!c->remain.buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	get_save_registers(c, &nb_reg, &first, &hmac_nb_reg, &hmac_first);

	c->csr = calloc(nb_reg + hmac_nb_reg, sizeof(uint32_t));
	if (!c->csr) {
		free(c->remain.buf);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	return TEE_SUCCESS;
}

void stm32_hash_free(struct stm32_hash_context *c)
{
	if (!c)
		return;

	free(c->remain.buf);
	free(c->csr);
}

TEE_Result stm32_hash_update(struct stm32_hash_context *c,
			     const uint8_t *buffer, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t next_queue_size = c->queue_size;
	vaddr_t base = 0;

	assert(c);

	base = c->dev->pdata.base;

	if (!len || !buffer)
		return TEE_SUCCESS;

	mutex_lock(&c->dev->lock);
	if (clk_enable(c->dev->pdata.clock)) {
		EMSG("Fail to enable clk %s",
		     clk_get_name(c->dev->pdata.clock));
		panic();
	}

	res = restore_context(c);
	if (res)
		goto exit;

	/* We cannot fill the fifo */
	if (c->remain.len + len < c->queue_size) {
		if (!c->remain.buf) {
			res = TEE_ERROR_BAD_STATE;
			goto exit;
		}

		memcpy(((uint8_t *)c->remain.buf) + c->remain.len, buffer, len);
		c->remain.len += len;

		/*
		 * We don't need to save status as we didn't change IP
		 * internal state.
		 */
		goto exit;
	} else {
		next_queue_size = c->block_size;
	}

	/* First write data saved in previous update */
	if (c->remain.len) {
		size_t align = 0;
		size_t i = 0;

		if (!c->remain.buf) {
			res = TEE_ERROR_BAD_STATE;
			goto exit;
		}

		/* Add bytes needed to align saved data */
		align = ROUNDUP(c->remain.len, sizeof(uint32_t)) -
			c->remain.len;
		memcpy(((uint8_t *)c->remain.buf) + c->remain.len, buffer,
		       align);
		c->remain.len += align;
		buffer += align;
		len -= align;

		for (i = 0; i < c->remain.len / sizeof(uint32_t); i++) {
			res = hash_write_data(base, c->remain.buf[i]);
			if (res)
				goto exit;

			c->remain.buf[i] = 0; /* Reset to 0 */
		}

		/* No more saved data */
		c->remain.len = 0;
	}

	/*
	 * Here, the data should be written to the FIFO until we cannot
	 * guarantee anymore that the data that we write will trigger a
	 * process of data. Then we write the remaining data until DINIS
	 * is set to 1 by hardware, meaning that a complete block can be
	 * sent. Data written will be saved during save_context() and
	 * remaining data not written (if there's any) will be saved in
	 * c->remain.buf.
	 */
	while (len >= c->queue_size ||
	       !(io_read32(base + _HASH_SR) & _HASH_SR_DINIS)) {
		uint32_t tmp_buf = 0;

		memcpy(&tmp_buf, buffer, sizeof(uint32_t));
		res = hash_write_data(base, tmp_buf);
		if (res)
			goto exit;

		buffer += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}

	c->queue_size = next_queue_size;

	if (len) {
		assert(c->remain.len == 0);

		if (!c->remain.buf) {
			res = TEE_ERROR_BAD_STATE;
			goto exit;
		}

		memcpy(c->remain.buf, buffer, len);
		c->remain.len = len;
	}

	res = save_context(c);

exit:
	clk_disable(c->dev->pdata.clock);
	mutex_unlock(&c->dev->lock);

	return res;
}

TEE_Result stm32_hash_final(struct stm32_hash_context *c, uint8_t *digest,
			    const uint8_t *key, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t base = 0;

	assert(c);

	base = c->dev->pdata.base;

	if ((!key || !len) && c->mode != STM32_HASH_MODE)
		return TEE_ERROR_BAD_STATE;

	mutex_lock(&c->dev->lock);
	if (clk_enable(c->dev->pdata.clock)) {
		EMSG("Fail to enable clk %s",
		     clk_get_name(c->dev->pdata.clock));
		panic();
	}

	res = restore_context(c);
	if (res)
		goto exit;

	if (c->remain.len) {
		size_t i = 0;

		for (i = 0;
		     i < ROUNDUP_DIV(c->remain.len, sizeof(uint32_t));
		     i++) {
			res = hash_write_data(base, c->remain.buf[i]);
			if (res)
				goto exit;
			c->remain.buf[i] = 0; /* Reset to 0 */
		}

		io_clrsetbits32(base + _HASH_STR, _HASH_STR_NBLW_MASK,
				8 * (c->remain.len % sizeof(uint32_t)));

		/* No more saved data */
		c->remain.len = 0;
	} else {
		io_clrbits32(base + _HASH_STR, _HASH_STR_NBLW_MASK);
	}

	io_setbits32(base + _HASH_STR, _HASH_STR_DCAL);

	if (c->mode == STM32_HMAC_MODE) {
		res = write_key(base, key, len);
		if (res)
			goto exit;
	}

	res = hash_get_digest(c, digest);

exit:
	clk_disable(c->dev->pdata.clock);
	mutex_unlock(&c->dev->lock);

	return res;
}

TEE_Result stm32_hash_init(struct stm32_hash_context *c, const uint8_t *key,
			   size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(c);

	if ((!key || !len) && c->mode != STM32_HASH_MODE)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&c->dev->lock);

	if (clk_enable(c->dev->pdata.clock)) {
		EMSG("Fail to enable clk %s",
		     clk_get_name(c->dev->pdata.clock));
		panic();
	}

	c->remain.len = 0;
	/* First queue is block_size + one register */
	c->queue_size = c->block_size + sizeof(uint32_t);
	memset(c->remain.buf, 0, c->queue_size);

	res = hw_init(c, key, len);
	if (res)
		goto exit;

	res = save_context(c);

exit:
	clk_disable(c->dev->pdata.clock);
	mutex_unlock(&c->dev->lock);

	return res;
}

static TEE_Result stm32_hash_parse_fdt(struct stm32_hash_platdata *pdata,
				       const void *fdt, int node,
				       const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t reg_size = 0;
	paddr_t reg = 0;

	res = rstctrl_dt_get_by_index(fdt, node, 0, &pdata->reset);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	res = clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
	if (res)
		return res;

	res = fdt_reg_info(fdt, node, &reg, &reg_size);
	if (res)
		return res;

	pdata->base = (vaddr_t)phys_to_virt(reg, MEM_AREA_IO_SEC, reg_size);
	if (!pdata->base)
		panic();

	pdata->compat = (struct stm32_hash_compat *)compat_data;

	return TEE_SUCCESS;
}

static TEE_Result stm32_hash_probe(const void *fdt, int node,
				   const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t __maybe_unused rev = 0;
	struct stm32_hash_platdata temp_pdata = { };

	res = stm32_hash_parse_fdt(&temp_pdata, fdt, node, compat_data);
	if (res)
		return res;

	stm32_hash = calloc(1, sizeof(*stm32_hash));
	if (!stm32_hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	stm32_hash->pdata = temp_pdata;

	if (clk_enable(stm32_hash->pdata.clock)) {
		EMSG("Fail to enable clk %s",
		     clk_get_name(stm32_hash->pdata.clock));
		panic();
	}

	rev = io_read32(stm32_hash->pdata.base + _HASH_VERR);
	FMSG("STM32 HASH v%"PRIu32".%"PRIu32, (rev & _HASH_VERR_MAJREV) >> 4,
	     rev & _HASH_VERR_MINREV);

	if (stm32_hash->pdata.reset &&
	    rstctrl_assert_to(stm32_hash->pdata.reset, RESET_TIMEOUT_US_1MS))
		panic();

	if (stm32_hash->pdata.reset &&
	    rstctrl_deassert_to(stm32_hash->pdata.reset, RESET_TIMEOUT_US_1MS))
		panic();

	mutex_init(&stm32_hash->lock);

	clk_disable(stm32_hash->pdata.clock);

	if (IS_ENABLED(CFG_CRYPTO_DRV_HASH)) {
		res = stm32_register_hash();
		if (res) {
			EMSG("Failed to register to HASH: %#"PRIx32, res);
			panic();
		}
	}

	if (IS_ENABLED(CFG_CRYPTO_DRV_MAC)) {
		res = stm32_register_hmac();
		if (res) {
			EMSG("Failed to register to HMAC : %#"PRIx32, res);
			panic();
		}
	}

	return TEE_SUCCESS;
}

static const struct stm32_hash_compat mp13_compat = {
	.caps = CAPS_SHA1 | CAPS_SHA2_224 | CAPS_SHA2_256 | CAPS_SHA2_384 |
		CAPS_SHA2_512 | CAPS_SHA3,
};

static const struct stm32_hash_compat mp15_compat = {
	.caps = CAPS_MD5 | CAPS_SHA1 | CAPS_SHA2_224 | CAPS_SHA2_256,
};

static const struct dt_device_match hash_match_table[] = {
	{ .compatible = "st,stm32mp13-hash", .compat_data = &mp13_compat },
	{ .compatible = "st,stm32f756-hash", .compat_data = &mp15_compat },
	{ }
};

DEFINE_DT_DRIVER(stm32_hash_dt_driver) = {
	.name = "stm32-hash",
	.match_table = hash_match_table,
	.probe = &stm32_hash_probe,
};
