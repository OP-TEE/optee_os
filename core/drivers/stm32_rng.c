// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_rng.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <string.h>

#define DT_RNG_COMPAT		"st,stm32-rng"
#define RNG_CR			0x00U
#define RNG_SR			0x04U
#define RNG_DR			0x08U

#define RNG_CR_RNGEN		BIT(2)
#define RNG_CR_IE		BIT(3)
#define RNG_CR_CED		BIT(5)

#define RNG_SR_DRDY		BIT(0)
#define RNG_SR_CECS		BIT(1)
#define RNG_SR_SECS		BIT(2)
#define RNG_SR_CEIS		BIT(5)
#define RNG_SR_SEIS		BIT(6)

#define RNG_TIMEOUT_US		10000

struct stm32_rng_instance {
	struct io_pa_va base;
	unsigned long clock;
	unsigned int lock;
	unsigned int refcount;
};

static struct stm32_rng_instance *stm32_rng;

/*
 * Extracts from the STM32 RNG specification:
 *
 * When a noise source (or seed) error occurs, the RNG stops generating
 * random numbers and sets to “1” both SEIS and SECS bits to indicate
 * that a seed error occurred. (...)

 * The following sequence shall be used to fully recover from a seed
 * error after the RNG initialization:
 * 1. Clear the SEIS bit by writing it to “0”.
 * 2. Read out 12 words from the RNG_DR register, and discard each of
 * them in order to clean the pipeline.
 * 3. Confirm that SEIS is still cleared. Random number generation is
 * back to normal.
 */
static void conceal_seed_error(vaddr_t rng_base)
{
	if (io_read32(rng_base + RNG_SR) & (RNG_SR_SECS | RNG_SR_SEIS)) {
		size_t i = 0;

		io_mask32(rng_base + RNG_SR, 0, RNG_SR_SEIS);

		for (i = 12; i != 0; i--)
			(void)io_read32(rng_base + RNG_DR);

		if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS)
			panic("RNG noise");
	}
}

#define RNG_FIFO_BYTE_DEPTH		16u

TEE_Result stm32_rng_read_raw(vaddr_t rng_base, uint8_t *out, size_t *size)
{
	bool enabled = false;
	TEE_Result rc = TEE_ERROR_SECURITY;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	uint64_t timeout_ref = timeout_init_us(RNG_TIMEOUT_US);

	if (!(io_read32(rng_base + RNG_CR) & RNG_CR_RNGEN)) {
		/* Enable RNG if not, clock error is disabled */
		io_write32(rng_base + RNG_CR, RNG_CR_RNGEN | RNG_CR_CED);
		enabled = true;
	}

	/* Wait RNG has produced well seeded random samples */
	while (!timeout_elapsed(timeout_ref)) {
		conceal_seed_error(rng_base);

		if (io_read32(rng_base + RNG_SR) & RNG_SR_DRDY)
			break;
	}

	if (io_read32(rng_base + RNG_SR) & RNG_SR_DRDY) {
		uint8_t *buf = out;
		size_t req_size = MIN(RNG_FIFO_BYTE_DEPTH, *size);
		size_t len = req_size;

		/* RNG is ready: read up to 4 32bit words */
		while (len) {
			uint32_t data32 = io_read32(rng_base + RNG_DR);
			size_t sz = MIN(len, sizeof(uint32_t));

			memcpy(buf, &data32, sz);
			buf += sz;
			len -= sz;
		}
		rc = TEE_SUCCESS;
		*size = req_size;
	}

	if (enabled)
		io_write32(rng_base + RNG_CR, 0);

	thread_unmask_exceptions(exceptions);

	return rc;
}

static void gate_rng(bool enable, struct stm32_rng_instance *dev)
{
	vaddr_t rng_cr = io_pa_or_va(&dev->base, 1) + RNG_CR;
	uint32_t exceptions = may_spin_lock(&dev->lock);

	if (enable) {
		/* incr_refcnt return non zero if resource shall be enabled */
		if (incr_refcnt(&dev->refcount)) {
			stm32_clock_enable(dev->clock);
			io_write32(rng_cr, 0);
			io_write32(rng_cr, RNG_CR_RNGEN | RNG_CR_CED);
		}
	} else {
		/* decr_refcnt return non zero if resource shall be disabled */
		if (decr_refcnt(&dev->refcount)) {
			io_write32(rng_cr, 0);
			stm32_clock_disable(dev->clock);
		}
	}

	may_spin_unlock(&dev->lock, exceptions);
}

TEE_Result stm32_rng_read(uint8_t *out, size_t size)
{
	TEE_Result rc = 0;
	uint32_t exceptions = 0;
	vaddr_t rng_base = io_pa_or_va(&stm32_rng->base, 1);
	uint8_t *out_ptr = out;
	size_t out_size = 0;

	if (!stm32_rng) {
		DMSG("No RNG");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	gate_rng(true, stm32_rng);

	while (out_size < size) {
		/* Read by chunks of the size the RNG FIFO depth */
		size_t sz = size - out_size;

		exceptions = may_spin_lock(&stm32_rng->lock);

		rc = stm32_rng_read_raw(rng_base, out_ptr, &sz);

		may_spin_unlock(&stm32_rng->lock, exceptions);

		if (rc)
			goto bail;

		out_size += sz;
		out_ptr += sz;
	}

bail:
	gate_rng(false, stm32_rng);
	if (rc)
		memset(out, 0, size);

	return rc;
}

#ifdef CFG_EMBED_DTB
static TEE_Result stm32_rng_init(void)
{
	void *fdt = NULL;
	int node = -1;
	struct dt_node_info dt_info;
	enum teecore_memtypes mtype = MEM_AREA_END;

	memset(&dt_info, 0, sizeof(dt_info));

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	while (true) {
		node = fdt_node_offset_by_compatible(fdt, node, DT_RNG_COMPAT);
		if (node < 0)
			break;

		_fdt_fill_device_info(fdt, &dt_info, node);

		if (!(dt_info.status & DT_STATUS_OK_SEC))
			continue;

		if (stm32_rng)
			panic();

		stm32_rng = calloc(1, sizeof(*stm32_rng));
		if (!stm32_rng)
			panic();

		assert(dt_info.clock != DT_INFO_INVALID_CLOCK &&
		       dt_info.reg != DT_INFO_INVALID_REG);

		if (dt_info.status & DT_STATUS_OK_NSEC) {
			stm32mp_register_non_secure_periph_iomem(dt_info.reg);
			mtype = MEM_AREA_IO_NSEC;
		} else {
			stm32mp_register_secure_periph_iomem(dt_info.reg);
			mtype = MEM_AREA_IO_SEC;
		}

		stm32_rng->base.pa = dt_info.reg;
		stm32_rng->base.va = (vaddr_t)phys_to_virt(dt_info.reg, mtype,
							   1);

		stm32_rng->clock = (unsigned long)dt_info.clock;

		DMSG("RNG init");
	}

	return TEE_SUCCESS;
}

driver_init(stm32_rng_init);
#endif /*CFG_EMBED_DTB*/
