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
#define SYSCFG_IOCTRLSETR			U(0x18)
#define SYSCFG_CMPCR				U(0x20)
#define SYSCFG_CMPENSETR			U(0x24)
#define SYSCFG_CMPSD1CR				U(0x30)
#define SYSCFG_CMPSD2CR				U(0x40)
#define SYSCFG_HSLVEN0R				U(0x50)
#define SYSCFG_IOSIZE				U(0x400)

/*
 * SYSCFG_IOCTRLSETR Register for STM32MP15 variants
 */
#define SYSCFG_IOCTRLSETR_HSLVEN_TRACE		BIT(0)
#define SYSCFG_IOCTRLSETR_HSLVEN_QUADSPI	BIT(1)
#define SYSCFG_IOCTRLSETR_HSLVEN_ETH		BIT(2)
#define SYSCFG_IOCTRLSETR_HSLVEN_SDMMC		BIT(3)
#define SYSCFG_IOCTRLSETR_HSLVEN_SPI		BIT(4)

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

/*
 * HSLV definitions
 */
#define SYSCFG_HSLV_MASK			GENMASK_32(15, 0)
#define SYSCFG_HSLV_KEY				U(0x1018)

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

	/* Copy APSRC (resp. ANSRC) in RAPSRC (resp. RANSRC) */
	apsrc_ansrc = value_cmpcr >> SYSCFG_CMPCR_ANSRC_SHIFT;
	value_cmpcr &= ~(SYSCFG_CMPCR_RANSRC | SYSCFG_CMPCR_RAPSRC);
	value_cmpcr |= SHIFT_U32(apsrc_ansrc, SYSCFG_CMPCR_RANSRC_SHIFT);

	io_write32(cmpcr_base, value_cmpcr | SYSCFG_CMPCR_SW_CTRL);

	io_setbits32(cmpcr_base + CMPENCLRR_OFFSET, SYSCFG_CMPENSETR_MPU_EN);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(cmpcr_base));
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

void stm32mp_set_hslv_state(enum stm32mp13_hslv_id id, bool enable)
{
	size_t hslvenxr_offset = 0;
	uint32_t hlvs_value = 0;

	assert(id < SYSCFG_HSLV_COUNT);

	if (enable)
		hlvs_value = SYSCFG_HSLV_KEY;

	/* IDs are indices of SYSCFG_HSLVENxR registers */
	hslvenxr_offset = SYSCFG_HSLVEN0R + id * sizeof(uint32_t);

	io_write32(get_syscfg_base() + hslvenxr_offset, hlvs_value);

	/* Value read shall be 1 on enable and 0 on disable */
	hlvs_value = io_read32(get_syscfg_base() + hslvenxr_offset) &
		     SYSCFG_HSLV_MASK;
	if (enable != hlvs_value)
		panic();
}

void stm32mp_enable_fixed_vdd_hslv(void)
{
	enum stm32mp13_hslv_id id = SYSCFG_HSLV_COUNT;

	for (id = SYSCFG_HSLV_IDX_TPIU; id < SYSCFG_HSLV_COUNT; id++) {
		/* SDMMCs domains may not be supplied by VDD */
		if (id == SYSCFG_HSLV_IDX_SDMMC1 ||
		    id == SYSCFG_HSLV_IDX_SDMMC2)
			continue;

		stm32mp_set_hslv_state(id, true);
	}
}
#endif /* CFG_STM32MP13 */

#ifdef CFG_STM32MP15
void stm32mp_enable_fixed_vdd_hslv(void)
{
	io_write32(get_syscfg_base() + SYSCFG_IOCTRLSETR,
		   SYSCFG_IOCTRLSETR_HSLVEN_TRACE |
		   SYSCFG_IOCTRLSETR_HSLVEN_QUADSPI |
		   SYSCFG_IOCTRLSETR_HSLVEN_ETH |
		   SYSCFG_IOCTRLSETR_HSLVEN_SDMMC |
		   SYSCFG_IOCTRLSETR_HSLVEN_SPI);
}
#endif
