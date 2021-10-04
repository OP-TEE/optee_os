// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <config.h>
#include <drivers/zynqmp_csudma.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <util.h>

#define CSUDMA_ADDR_OFFSET		0x00
#define CSUDMA_SIZE_OFFSET		0x04
#define CSUDMA_STS_OFFSET		0x08
#define CSUDMA_CTRL_OFFSET		0x0C
#define CSUDMA_CRC_OFFSET		0x10
#define CSUDMA_I_STS_OFFSET		0x14
#define CSUDMA_I_EN_OFFSET		0x18
#define CSUDMA_I_DIS_OFFSET		0x1C
#define CSUDMA_I_MASK_OFFSET		0x20
#define CSUDMA_CTRL2_OFFSET		0x24
#define CSUDMA_ADDR_MSB_OFFSET		0x28

#define CSUDMA_OFFSET_DIFF		0x0800

#define CSUDMA_ADDR_MASK		GENMASK_32(31, 2)
#define CSUDMA_ADDR_LSB_MASK		(BIT(0) | BIT(1))
#define CSUDMA_ADDR_MSB_MASK		GENMASK_32(16, 0)
#define CSUDMA_ADDR_MSB_SHIFT		32
#define CSUDMA_SIZE_SHIFT		2
#define CSUDMA_STS_BUSY_MASK		BIT(0)
#define CSUDMA_CTRL_ENDIAN_MASK		BIT(23)
#define CSUDMA_LAST_WORD_MASK		BIT(0)
#define CSUDMA_IXR_DONE_MASK		BIT(1)
#define CSUDMA_IXR_SRC_MASK		GENMASK_32(6, 0)
#define CSUDMA_IXR_DST_MASK		GENMASK_32(7, 1)

#define CSUDMA_DONE_TIMEOUT_USEC	3000000

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CSUDMA_BASE, CSUDMA_SIZE);

static void csudma_clear_intr(enum zynqmp_csudma_channel channel, uint32_t mask)
{
	vaddr_t dma = core_mmu_get_va(CSUDMA_BASE, MEM_AREA_IO_SEC,
				      CSUDMA_SIZE);
	uint32_t val = CSUDMA_IXR_SRC_MASK;

	if (channel == ZYNQMP_CSUDMA_DST_CHANNEL) {
		dma += CSUDMA_OFFSET_DIFF;
		val = CSUDMA_IXR_DST_MASK;
	}

	io_write32(dma + CSUDMA_I_STS_OFFSET, val & mask);
}

TEE_Result zynqmp_csudma_sync(enum zynqmp_csudma_channel channel)
{
	vaddr_t dma = core_mmu_get_va(CSUDMA_BASE, MEM_AREA_IO_SEC,
				      CSUDMA_SIZE);
	uint64_t tref = timeout_init_us(CSUDMA_DONE_TIMEOUT_USEC);
	uint32_t status = 0;

	if (!dma)
		return TEE_ERROR_GENERIC;

	if (channel == ZYNQMP_CSUDMA_DST_CHANNEL)
		dma = dma + CSUDMA_OFFSET_DIFF;

	while (!timeout_elapsed(tref)) {
		status = io_read32(dma + CSUDMA_I_STS_OFFSET);
		if ((status & CSUDMA_IXR_DONE_MASK) == CSUDMA_IXR_DONE_MASK) {
			csudma_clear_intr(channel, CSUDMA_IXR_DONE_MASK);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_GENERIC;
}

TEE_Result zynqmp_csudma_prepare(void)
{
	vaddr_t dma = core_mmu_get_va(CSUDMA_BASE, MEM_AREA_IO_SEC,
				      CSUDMA_SIZE);

	if (!dma)
		return TEE_ERROR_GENERIC;

	io_setbits32(dma + CSUDMA_CTRL_OFFSET, CSUDMA_CTRL_ENDIAN_MASK);
	dma = dma + CSUDMA_OFFSET_DIFF;
	io_setbits32(dma + CSUDMA_CTRL_OFFSET, CSUDMA_CTRL_ENDIAN_MASK);

	return TEE_SUCCESS;
}

void zynqmp_csudma_unprepare(void)
{
	vaddr_t dma = core_mmu_get_va(CSUDMA_BASE, MEM_AREA_IO_SEC,
				      CSUDMA_SIZE);

	io_clrbits32(dma + CSUDMA_CTRL_OFFSET, CSUDMA_CTRL_ENDIAN_MASK);
	dma = dma + CSUDMA_OFFSET_DIFF;
	io_clrbits32(dma + CSUDMA_CTRL_OFFSET, CSUDMA_CTRL_ENDIAN_MASK);
}

TEE_Result zynqmp_csudma_transfer(enum zynqmp_csudma_channel channel,
				  void *addr, size_t len, uint8_t notify)
{
	vaddr_t dma = core_mmu_get_va(CSUDMA_BASE, MEM_AREA_IO_SEC,
				      CSUDMA_SIZE);
	paddr_t phys = virt_to_phys(addr);
	uint32_t addr_offset = 0;

	if (!dma)
		return TEE_ERROR_GENERIC;

	if (len % sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ALIGNED(phys, ZYNQMP_CSUDMA_ALIGN)) {
		EMSG("Invalid alignment");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* convert to 32 bit word transfers */
	len = len / sizeof(uint32_t);

	if (channel == ZYNQMP_CSUDMA_DST_CHANNEL) {
		dma = dma + CSUDMA_OFFSET_DIFF;
		dcache_inv_range(addr, SHIFT_U64(len, CSUDMA_SIZE_SHIFT));
	} else {
		dcache_clean_range(addr, SHIFT_U64(len, CSUDMA_SIZE_SHIFT));
	}

	addr_offset = phys & CSUDMA_ADDR_MASK;
	io_write32(dma + CSUDMA_ADDR_OFFSET, addr_offset);

	addr_offset = phys >> CSUDMA_ADDR_MSB_SHIFT;
	io_write32(dma + CSUDMA_ADDR_MSB_OFFSET, addr_offset);
	io_write32(dma + CSUDMA_SIZE_OFFSET,
		   SHIFT_U32(len, CSUDMA_SIZE_SHIFT) | notify);

	return TEE_SUCCESS;
}
