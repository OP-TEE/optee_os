// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2020, STMicroelectronics
 */

#include <dt-bindings/clock/stm32mp1-clks.h>
#include <initcall.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <io.h>
#include <trace.h>
#include <types_ext.h>

/*
 * SYSCFG register offsets (base relative)
 */
#define SYSCFG_CMPCR				0x20U
#define SYSCFG_CMPENSETR			0x24U

/*
 * SYSCFG_CMPCR Register
 */
#define SYSCFG_CMPCR_SW_CTRL			BIT(1)
#define SYSCFG_CMPCR_READY			BIT(8)
#define SYSCFG_CMPCR_RANSRC			GENMASK_32(19, 16)
#define SYSCFG_CMPCR_RANSRC_SHIFT		16
#define SYSCFG_CMPCR_RAPSRC			GENMASK_32(23, 20)
#define SYSCFG_CMPCR_ANSRC_SHIFT		24

#define SYSCFG_CMPCR_READY_TIMEOUT_US		1000U

/*
 * SYSCFG_CMPENSETR Register
 */
#define SYSCFG_CMPENSETR_MPU_EN			BIT(0)

static vaddr_t get_syscfg_base(void)
{
	struct io_pa_va base = { .pa = SYSCFG_BASE };

	return io_pa_or_va(&base, 1);
}

void stm32mp_syscfg_enable_io_compensation(void)
{
	vaddr_t syscfg_base = get_syscfg_base();
	uint64_t timeout_ref = 0;

	stm32_clock_enable(CK_CSI);
	stm32_clock_enable(SYSCFG);

	io_setbits32(syscfg_base + SYSCFG_CMPENSETR, SYSCFG_CMPENSETR_MPU_EN);

	timeout_ref = timeout_init_us(SYSCFG_CMPCR_READY_TIMEOUT_US);

	while (!(io_read32(syscfg_base + SYSCFG_CMPCR) & SYSCFG_CMPCR_READY))
		if (timeout_elapsed(timeout_ref)) {
			EMSG("IO compensation cell not ready");
			/* Allow an almost silent failure here */
			break;
		}

	io_clrbits32(syscfg_base + SYSCFG_CMPCR, SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(syscfg_base + SYSCFG_CMPCR));
}

void stm32mp_syscfg_disable_io_compensation(void)
{
	vaddr_t syscfg_base = get_syscfg_base();
	uint32_t value = 0;

	value = io_read32(syscfg_base + SYSCFG_CMPCR) >>
		SYSCFG_CMPCR_ANSRC_SHIFT;

	io_clrbits32(syscfg_base + SYSCFG_CMPCR,
		     SYSCFG_CMPCR_RANSRC | SYSCFG_CMPCR_RAPSRC);

	value = io_read32(syscfg_base + SYSCFG_CMPCR) |
		(value << SYSCFG_CMPCR_RANSRC_SHIFT);

	io_write32(syscfg_base + SYSCFG_CMPCR, value | SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(syscfg_base + SYSCFG_CMPCR));

	io_clrbits32(syscfg_base + SYSCFG_CMPENSETR, SYSCFG_CMPENSETR_MPU_EN);

	stm32_clock_disable(SYSCFG);
	stm32_clock_disable(CK_CSI);
}

static TEE_Result stm32mp1_iocomp(void)
{
	stm32mp_syscfg_enable_io_compensation();

	return TEE_SUCCESS;
}
driver_init(stm32mp1_iocomp);
