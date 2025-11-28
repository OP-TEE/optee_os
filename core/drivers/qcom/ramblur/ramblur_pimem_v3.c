// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <config.h>
#include <drivers/qcom/ramblur/v3/ramblur_pimem_hwio.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>

#define ANTIROLLBACK	(UINT32_C(1) << \
	RAMBLUR_WIN0_ALGORITHM_ANTIROLLBACK_ENABLE_SHFT)
#define INTEGRITY	(UINT32_C(1) << \
	RAMBLUR_WIN0_ALGORITHM_INTEGRITY_ENABLE_SHFT)
#define CONFIDENTIALITY	(UINT32_C(1) << \
	RAMBLUR_WIN0_ALGORITHM_CONFIDENTIALITY_ENABLE_SHFT)

static vaddr_t ramblur_va;
static struct {
	uint32_t major;
	uint32_t minor;
	uint32_t step;
} ramblur_version;

static inline uint16_t in_word(uint32_t offset)
{
	return io_read16(ramblur_va + (vaddr_t)offset);
}

static inline uint32_t in_dword(uint32_t offset)
{
	return io_read32(ramblur_va + (vaddr_t)offset);
}

static inline void out_dword(uint32_t offset, uint32_t val)
{
	io_write32(ramblur_va + (vaddr_t)offset, val);
}

static inline uint32_t in_dword_masked(uint32_t offset, uint32_t mask)
{
	return in_dword(offset) & mask;
}

static inline void out_dword_masked_ns(uint32_t offset, uint32_t mask,
				       uint32_t val, uint32_t current_val)
{
	uint32_t new_val;

	new_val = (current_val & ~mask) | (val & mask);
	out_dword(offset, new_val);
}

static inline void readback_sync(uint32_t reg, uint32_t val, uint32_t mask,
				 uint32_t shift)
{
	if (shift > 31)
		panic();

	dsb();
	while (val != (in_dword_masked(reg, mask) >> shift))
		;
}

static void enable(int window)
{
	uint32_t mask = RAMBLUR_WINn_CTL_WIN_ENABLE_BMSK;
	uint32_t reg = RAMBLUR_WINn_CTL_ADDR(window);
	uint32_t val = BIT(RAMBLUR_WINn_CTL_WIN_ENABLE_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_WINn_CTL_INI(window));

	reg = RAMBLUR_WINn_STATUS_ADDR(window);
	mask = RAMBLUR_WINn_STATUS_WIN_ENABLE_STATUS_BMSK;
	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_WINn_STATUS_WIN_ENABLE_STATUS_SHFT;
	} while (val != 1U);
}

static void disable_sw_init_mode(int window)
{
	uint32_t mask = RAMBLUR_WINn_CTL_SW_INIT_MODE_BMSK;
	uint32_t reg = RAMBLUR_WINn_CTL_ADDR(window);
	uint32_t val = 0;

	out_dword_masked_ns(reg, mask, val, RAMBLUR_WINn_CTL_INI(window));
	readback_sync(reg, val, mask, RAMBLUR_WINn_CTL_SW_INIT_MODE_SHFT);
}

static void disable(int window)
{
	uint32_t mask = RAMBLUR_WINn_CTL_WIN_DISABLE_BMSK;
	uint32_t reg = RAMBLUR_WINn_CTL_ADDR(window);
	uint32_t val = BIT(RAMBLUR_WINn_CTL_WIN_DISABLE_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_WINn_CTL_INI(window));

	mask = RAMBLUR_WINn_STATUS_WIN_ENABLE_STATUS_BMSK;
	reg = RAMBLUR_WINn_STATUS_ADDR(window);
	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_WINn_STATUS_WIN_ENABLE_STATUS_SHFT;
	} while (val != 0U);
}

static void set_hw_init(int window, uint32_t offset)
{
	uint32_t mask = RAMBLUR_WINn_HW_INIT_START_BMSK;
	uint32_t reg = RAMBLUR_WINn_HW_INIT_START_ADDR(window);
	uint32_t cur = RAMBLUR_WINn_HW_INIT_START_INI(window);
	uint32_t val = offset;

	out_dword_masked_ns(reg, mask, val, cur);
	readback_sync(reg, val & mask, mask, 0);
}

static void initialize_hardware_v3_0(int window)
{
	int skip = 6; /* stabilize output */
	uint32_t mask = RAMBLUR_WINn_STATUS_HW_INIT_IN_PROGRESS_BMSK;
	uint32_t reg = RAMBLUR_WINn_STATUS_ADDR(window);
	uint32_t val = 0;

	/*
	 * pIMEM 3.0: HW_INIT_IN_PROGRESS updates only after ~6 cycles.
	 * Because the first write is posted, the immediate read may return 0.
	 * Issuing a few back-to-back reads ensures the bit has settled.
	 */
	do {
		val = in_dword_masked(reg, mask) >>
		      RAMBLUR_WINn_STATUS_HW_INIT_IN_PROGRESS_SHFT;

		if (skip > 0) {
			skip--;
			continue;
		}

	} while (val != 0);
}

static void initialize_hardware_v3_x(int window)
{
	uint32_t mask = RAMBLUR_WINn_STATUS_HW_INIT_DONE_BMSK;
	uint32_t reg = RAMBLUR_WINn_STATUS_ADDR(window);
	uint32_t val = 0;

	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_WINn_STATUS_HW_INIT_DONE_SHFT;
	} while (val != 1U);
}

static void initialize_hardware(int window)
{
	uint32_t mask = RAMBLUR_WINn_CTL_START_HW_INIT_BMSK;
	uint32_t reg = RAMBLUR_WINn_CTL_ADDR(window);
	uint32_t val = BIT(RAMBLUR_WINn_CTL_START_HW_INIT_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_WINn_CTL_INI(window));

	if (ramblur_version.minor > 0)
		return initialize_hardware_v3_x(window);

	return initialize_hardware_v3_0(window);
}

static void initialize(int window)
{
	const uint32_t offset = 0U;

	disable_sw_init_mode(window);
	disable(window);
	set_hw_init(window, offset);
	initialize_hardware(window);
}

static void set_security(int window, uint32_t algo)
{
	uint32_t reg = RAMBLUR_WINn_ALGORITHM_CONFIG_ADDR(window);

	out_dword(reg, algo);
	readback_sync(reg, algo, UINT32_MAX, 0);
}

static uint32_t get_size(int window)
{
	uint32_t reg = RAMBLUR_WINn_SIZE_ADDR(window);

	return in_dword_masked(reg, RAMBLUR_WINn_SIZE_RMSK);
}

static void set_size(int window, size_t size)
{
	uint32_t reg = RAMBLUR_WINn_SIZE_ADDR(window);
	uint32_t win_size = get_size(window);

	if (!win_size) {
		/* Initialize */
		out_dword(reg, (uint32_t)size);
		readback_sync(reg, size, RAMBLUR_WINn_SIZE_RMSK, 0);
	} else if (win_size < size) {
		/* We can not resize in this code path */
		panic("Can't increase pIMEM");
	} else {
		/* Requested fits what is already configured */
		IMSG("Ramblur pIMEM size reused");
	}
}

static void configure_vault(int window, uintptr_t addr)
{
	uint32_t hi = (uint32_t)(addr >> 32);
	uint32_t lo = (uint32_t)addr;
	uint32_t reg = 0;

	hi &= RAMBLUR_WINn_DATA_VAULT_ADDR_HI_RMSK;
	reg = RAMBLUR_WINn_DATA_VAULT_ADDR_HI_ADDR(window);
	out_dword(reg, hi);
	readback_sync(reg, hi, UINT32_MAX, 0);

	lo &= RAMBLUR_WINn_DATA_VAULT_ADDR_LOW_RMSK;
	reg = RAMBLUR_WINn_DATA_VAULT_ADDR_LOW_ADDR(window);
	out_dword(reg, lo);
	readback_sync(reg, lo, UINT32_MAX, 0);
}

static void get_hardware_version(uint32_t *major, uint32_t *minor,
				 uint32_t *step)
{
	uint32_t val = in_dword(RAMBLUR_VERSION_ADDR);

	*major = (val & RAMBLUR_VERSION_MAJOR_BMSK) >>
		RAMBLUR_VERSION_MAJOR_SHFT;
	*minor = (val & RAMBLUR_VERSION_MINOR_BMSK) >>
		RAMBLUR_VERSION_MINOR_SHFT;
	*step = (val & RAMBLUR_VERSION_STEP_BMSK) >>
		RAMBLUR_VERSION_STEP_SHFT;
}

static void pre_initialize_3_0_0(int window)
{
	uint32_t regs[2] = {
		RAMBLUR_WINn_DATA_TXN_QSB_CTL_ADDR(window),
		RAMBLUR_WINn_OVERHEAD_TXN_QSB_CTL_ADDR(window),
	};
	uint32_t masks[2] = {
		RAMBLUR_WINn_DATA_TXN_QSB_CTL_AINNERCACHEABLE_BMSK,
		RAMBLUR_WINn_OVERHEAD_TXN_QSB_CTL_AINNERCACHEABLE_BMSK,
	};
	uint32_t inis[2] = {
		RAMBLUR_WINn_DATA_TXN_QSB_CTL_INI(window),
		RAMBLUR_WINn_OVERHEAD_TXN_QSB_CTL_INI(window),
	};
	uint32_t shift[2] = {
		RAMBLUR_WINn_DATA_TXN_QSB_CTL_AINNERCACHEABLE_SHFT,
		RAMBLUR_WINn_OVERHEAD_TXN_QSB_CTL_AINNERCACHEABLE_SHFT,
	};

	for (int i = 0; i < 2; i++) {
		out_dword_masked_ns(regs[i], masks[i], 0x0, inis[i]);
		readback_sync(regs[i], 0, masks[i], shift[i]);
	}
}

/* This function might not return (panic) */
static TEE_Result initialize_window(int window, size_t size, uintptr_t vault)
{
	if (ramblur_version.major == 3 &&
	    ramblur_version.minor == 0 &&
	    ramblur_version.step == 0)
		pre_initialize_3_0_0(window);

	configure_vault(window, vault);
	set_size(window, size);
	set_security(window, ANTIROLLBACK | INTEGRITY | CONFIDENTIALITY);

	/* Wipes out the full window to 0x0 */
	initialize(window);
	enable(window);

	return TEE_SUCCESS;
}

/*
 * Trusted Applications run from protected IMEM.
 * If this region cannot be configured, abort the boot sequence.
 */
static TEE_Result qti_ramblur_pimem_init(void)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, RAMBLUR_PIMEM_REG_BASE,
				  RAMBLUR_PIMEM_REG_SIZE))
		panic("Can't add Ramblur pIMEM");

	ramblur_va = (vaddr_t)phys_to_virt(RAMBLUR_PIMEM_REG_BASE,
					   MEM_AREA_IO_SEC,
					   RAMBLUR_PIMEM_REG_SIZE);
	if (!ramblur_va)
		panic("Can't get Ramblur virtual");

	get_hardware_version(&ramblur_version.major,
			     &ramblur_version.minor,
			     &ramblur_version.step);

	DMSG("Ramblur pIMEM v%d.%d.%d (window=%d)",
	     ramblur_version.major,
	     ramblur_version.minor,
	     ramblur_version.step,
	     CFG_QCOM_RAMBLUR_TA_WINDOW_ID);

	if (ramblur_version.major != 3)
		panic();

	return initialize_window(CFG_QCOM_RAMBLUR_TA_WINDOW_ID,
				 RAMBLUR_PIMEM_VAULT_TA_SIZE,
				 RAMBLUR_PIMEM_VAULT_TA_BASE);
}
driver_init(qti_ramblur_pimem_init);
