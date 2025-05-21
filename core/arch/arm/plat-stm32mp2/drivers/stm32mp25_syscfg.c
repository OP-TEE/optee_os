// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/stm32_shared_io.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stm32_sysconf.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#define SYSCON_OFFSET(id)	((id) & GENMASK_32(15, 0))
#define SYSCON_BANK(id)		(((id) & GENMASK_32(31, 16)) >> 16)

#define SYSCFG_OCTOSPIAMCR			SYSCON_ID(SYSCON_SYSCFG, \
							  0x2C00U)
#define SYSCFG_OCTOSPIAMCR_OAM_MASK		GENMASK_32(2, 0)
#define SYSCFG_OCTOSPIAMCR_MM1_256_MM2_0	U(0)
#define SYSCFG_OCTOSPIAMCR_MM1_192_MM2_64	U(1)
#define SYSCFG_OCTOSPIAMCR_MM1_128_MM2_128	U(2)
#define SYSCFG_OCTOSPIAMCR_MM1_64_MM2_192	U(3)
#define SYSCFG_OCTOSPIAMCR_MM1_0_MM2_256	U(4)

#define SZ_64M					U(0x04000000)
#define SZ_128M					U(0x08000000)
#define SZ_192M					U(0x0C000000)
#define SZ_256M					U(0x10000000)

/* Safe Reset register definition */
#define SYSCFG_SAFERSTCR		SYSCON_ID(SYSCON_SYSCFG, U(0x2018))
#define SYSCFG_SAFERSTCR_EN		BIT(0)

struct io_pa_va syscfg_base[SYSCON_NB_BANKS] = {
	{ .pa = SYSCFG_BASE },
	{ .pa = A35SSC_BASE }
};

static vaddr_t stm32mp_syscfg_base(uint32_t id)
{
	uint32_t bank = SYSCON_BANK(id);

	assert(bank < SYSCON_NB_BANKS);

	return io_pa_or_va_secure(&syscfg_base[bank], 1);
}

void stm32mp_syscfg_write(uint32_t id, uint32_t value, uint32_t bitmsk)
{
	vaddr_t syconf_base = stm32mp_syscfg_base(id);

	io_mask32_stm32shregs(syconf_base + SYSCON_OFFSET(id), value, bitmsk);
}

uint32_t stm32mp_syscfg_read(uint32_t id)
{
	return io_read32(stm32mp_syscfg_base(id) + SYSCON_OFFSET(id));
}

void stm32mp25_syscfg_set_safe_reset(bool status)
{
	vaddr_t addr = stm32mp_syscfg_base(SYSCON_SYSCFG) + SYSCFG_SAFERSTCR;

	FMSG("Set safe reset to  %d", status);

	if (status)
		io_setbits32(addr, SYSCFG_SAFERSTCR_EN);
	else
		io_clrbits32(addr, SYSCFG_SAFERSTCR_EN);
}

void stm32mp25_syscfg_set_amcr(size_t mm1_size, size_t mm2_size)
{
	vaddr_t amcr_addr = stm32mp_syscfg_base(SYSCON_SYSCFG) +
			    SYSCON_OFFSET(SYSCFG_OCTOSPIAMCR);
	uint32_t amcr = 0;

	switch (mm1_size) {
	case 0:
		if (mm2_size != SZ_256M)
			panic();

		amcr = SYSCFG_OCTOSPIAMCR_MM1_0_MM2_256;
		break;
	case SZ_64M:
		if (mm2_size != SZ_192M)
			panic();

		amcr = SYSCFG_OCTOSPIAMCR_MM1_64_MM2_192;
		break;
	case SZ_128M:
		if (mm2_size != SZ_128M)
			panic();

		amcr = SYSCFG_OCTOSPIAMCR_MM1_128_MM2_128;
		break;
	case SZ_192M:
		if (mm2_size != SZ_64M)
			panic();

		amcr = SYSCFG_OCTOSPIAMCR_MM1_192_MM2_64;
		break;
	case SZ_256M:
		if (mm2_size != 0)
			panic();

		amcr = SYSCFG_OCTOSPIAMCR_MM1_256_MM2_0;
		break;
	default:
		panic();
	}

	io_clrsetbits32(amcr_addr, SYSCFG_OCTOSPIAMCR_OAM_MASK, amcr);
}
