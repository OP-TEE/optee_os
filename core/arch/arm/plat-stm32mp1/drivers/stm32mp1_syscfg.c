// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2023, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <drivers/stm32mp1_syscfg.h>
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
#define SYSCFG_CMPCR				U(0x20)
#define SYSCFG_CMPENSETR			U(0x24)
#define SYSCFG_CMPSD1CR				U(0x30)
#define SYSCFG_CMPSD2CR				U(0x40)
#define SYSCFG_IOSIZE				U(0x400)

/*
 * SYSCFG_CMPCR Register
 */
#define SYSCFG_CMPCR_SW_CTRL			BIT(1)
#define SYSCFG_CMPCR_READY			BIT(8)
#define SYSCFG_CMPCR_RANSRC			GENMASK_32(19, 16)
#define SYSCFG_CMPCR_RANSRC_SHIFT		U(16)
#define SYSCFG_CMPCR_RAPSRC			GENMASK_32(23, 20)
#define SYSCFG_CMPCR_ANSRC_SHIFT		U(24)

#define SYSCFG_CMPCR_READY_TIMEOUT_US		U(1000)

#define CMPENSETR_OFFSET			U(0x4)
#define CMPENCLRR_OFFSET			U(0x8)

/*
 * SYSCFG_CMPENSETR Register
 */
#define SYSCFG_CMPENSETR_MPU_EN			BIT(0)

static vaddr_t get_syscfg_base(void)
{
	static struct io_pa_va base = { .pa = SYSCFG_BASE };

	return io_pa_or_va(&base, SYSCFG_IOSIZE);
}

static void enable_io_compensation(int cmpcr_offset)
{
	vaddr_t cmpcr_va = get_syscfg_base() + cmpcr_offset;
	uint32_t value = 0;

	if (io_read32(cmpcr_va) & SYSCFG_CMPCR_READY)
		return;

	io_setbits32(cmpcr_va + CMPENSETR_OFFSET, SYSCFG_CMPENSETR_MPU_EN);

	if (IO_READ32_POLL_TIMEOUT(cmpcr_va, value, value & SYSCFG_CMPCR_READY,
				   0, SYSCFG_CMPCR_READY_TIMEOUT_US)) {
		/* Allow an almost silent failure here */
		EMSG("IO compensation cell not ready");
	}

	io_clrbits32(cmpcr_va, SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(cmpcr_va));
}

static __maybe_unused void disable_io_compensation(int cmpcr_offset)
{
	vaddr_t cmpcr_base = get_syscfg_base() + cmpcr_offset;
	uint32_t value_cmpcr = 0;
	uint32_t apsrc_ansrc = 0;
	uint32_t value_cmpcr2 = 0;

	value_cmpcr = io_read32(cmpcr_base);
	value_cmpcr2 = io_read32(cmpcr_base + CMPENSETR_OFFSET);
	if (!(value_cmpcr & SYSCFG_CMPCR_READY &&
	      value_cmpcr2 & SYSCFG_CMPENSETR_MPU_EN))
		return;

	/* Copy apsrc / ansrc in ransrc /rapsrc */
	apsrc_ansrc = value_cmpcr >> SYSCFG_CMPCR_ANSRC_SHIFT;
	value_cmpcr &= ~(SYSCFG_CMPCR_RANSRC | SYSCFG_CMPCR_RAPSRC);
	value_cmpcr |= SHIFT_U32(apsrc_ansrc, SYSCFG_CMPCR_RANSRC_SHIFT);

	io_write32(cmpcr_base, value_cmpcr | SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(cmpcr_base));

	io_setbits32(cmpcr_base + CMPENCLRR_OFFSET, SYSCFG_CMPENSETR_MPU_EN);
}

static TEE_Result stm32mp1_iocomp(void)
{
	if (clk_enable(stm32mp_rcc_clock_id_to_clk(CK_CSI)) ||
	    clk_enable(stm32mp_rcc_clock_id_to_clk(SYSCFG)))
		panic();

	enable_io_compensation(SYSCFG_CMPCR);

	return TEE_SUCCESS;
}

driver_init(stm32mp1_iocomp);

#ifdef CFG_STM32MP13
void stm32mp_set_vddsd_comp_state(enum stm32mp13_vddsd_comp_id id, bool enable)
{
	int cmpcr_offset = 0;

	switch (id) {
	case SYSCFG_IO_COMP_IDX_SD1:
		cmpcr_offset = SYSCFG_CMPSD1CR;
		break;
	case SYSCFG_IO_COMP_IDX_SD2:
		cmpcr_offset = SYSCFG_CMPSD2CR;
		break;
	default:
		panic();
	}

	if (enable)
		enable_io_compensation(cmpcr_offset);
	else
		disable_io_compensation(cmpcr_offset);
}
#endif /* CFG_STM32MP13 */
