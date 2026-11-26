// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <config.h>
#include <initcall.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/phys_mem.h>
#include <platform_config.h>
#include <string.h>
#include <util.h>

#define RAMBLUR_PIMEM_REG_SIZE		0x1000

#define RAMBLUR_VERSION			0x00
#define RAMBLUR_VERSION_MAJOR(v)	((v) >> 24)

/* Window 0 is fixed by the hardware; windows 1 to 3 follow it */
#define RAMBLUR_WINn_SIZE(n)		(0x10 + 0x8 * (n))
#define RAMBLUR_WIN_SIZE_MASK		GENMASK_32(26, 20)
#define RAMBLUR_WINn_ALGORITHM(n)	(0x14 + 0x8 * (n))
#define RAMBLUR_ALGO_CONFIDENTIALITY	BIT32(2)
#define RAMBLUR_ALGO_INTEGRITY		BIT32(1)

#define RAMBLUR_ESR			0x7c
#define RAMBLUR_ESR_VAULT_TXN_ERROR	BIT32(4)
#define RAMBLUR_ESR_AUTH_ERROR		BIT32(3)

#define RAMBLUR_WIN_INIT		0xd4
#define RAMBLUR_WIN_INIT_MODE(n)	BIT32(n)

#define RAMBLUR_WINDOWS			4
#define RAMBLUR_WIN_GRANULE		SIZE_1M
#define RAMBLUR_INIT_BLOCK		SMALL_PAGE_SIZE
#define RAMBLUR_POLL_TIMEOUT_US		1000

/* TA RAM, the TZDRAM above the TEE core, is the TA window */
#define TA_WIN_BASE			(TZDRAM_BASE + TEE_RAM_VA_SIZE)
#define TA_WIN_SIZE			(TZDRAM_SIZE - TEE_RAM_VA_SIZE)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, RAMBLUR_PIMEM_REG_BASE,
			RAMBLUR_PIMEM_REG_SIZE);

static vaddr_t ramblur_va;

static uint32_t win_size(int window)
{
	return io_read32(ramblur_va + RAMBLUR_WINn_SIZE(window)) &
	       RAMBLUR_WIN_SIZE_MASK;
}

/* A write that does not read back means a broken window: stop the boot */
static void wait_reg(uint32_t offset, uint32_t mask, uint32_t val)
{
	uint32_t v = 0;

	if (IO_READ32_POLL_TIMEOUT(ramblur_va + offset, v,
				   (v & mask) == val, 0,
				   RAMBLUR_POLL_TIMEOUT_US)) {
		EMSG("Ramblur pIMEM %#"PRIx32" reads %#"PRIx32", not %#"PRIx32,
		     offset, v & mask, val);
		panic();
	}
}

static void set_init_mode(int window, bool enable)
{
	uint32_t mask = RAMBLUR_WIN_INIT_MODE(window);
	uint32_t val = enable ? mask : 0;

	io_clrsetbits32(ramblur_va + RAMBLUR_WIN_INIT, mask, val);
	wait_reg(RAMBLUR_WIN_INIT, mask, val);
}

static void set_algorithm(int window, uint32_t algo)
{
	io_write32(ramblur_va + RAMBLUR_WINn_ALGORITHM(window), algo);
	wait_reg(RAMBLUR_WINn_ALGORITHM(window), UINT32_MAX, algo);
}

static void set_size(int window, uint32_t size)
{
	io_write32(ramblur_va + RAMBLUR_WINn_SIZE(window), size);
	wait_reg(RAMBLUR_WINn_SIZE(window), RAMBLUR_WIN_SIZE_MASK, size);
}

/*
 * A read of a line whose integrity tag was never written is an
 * authentication error: write the whole window once, in init mode,
 * so every tag is valid before the window is used.
 */
static void init_window(int window, paddr_t pa, size_t size)
{
	uint8_t *va = phys_to_virt(pa, MEM_AREA_SEC_RAM_OVERALL, size);
	size_t n = 0;

	if (!va)
		panic("Can't map the pIMEM TA window");

	/* Init mode first: the window is live, and readable, once sized */
	set_init_mode(window, true);
	/* Anti-rollback exists on window 0 only */
	set_algorithm(window, RAMBLUR_ALGO_INTEGRITY |
			      RAMBLUR_ALGO_CONFIDENTIALITY);
	set_size(window, size);

	for (n = 0; n < size; n += RAMBLUR_INIT_BLOCK) {
		memset(va + n, 0, RAMBLUR_INIT_BLOCK);
		dcache_clean_range(va + n, RAMBLUR_INIT_BLOCK);
	}
	dsb();

	set_init_mode(window, false);
}

static void check_window_unused(paddr_t pa, size_t size)
{
	size_t n = 0;

	for (n = 0; n < size; n += SMALL_PAGE_SIZE)
		if (phys_mem_mm_find(pa + n))
			panic("pIMEM TA window allocated before its init");
}

/*
 * The windows are laid out back to back in the pIMEM aperture, so the TA
 * window starts at the end of the windows below it, which XBL sized for
 * TZ. The TA window shares the physical memory pool with the core, which
 * allocates the lowest free pages first: the window stays unused only as
 * long as the free TEE RAM below it covers the boot allocations, which
 * check_window_unused() enforces.
 */
static TEE_Result qti_ramblur_pimem_init(void)
{
	const int window = CFG_QCOM_RAMBLUR_TA_WINDOW_ID;
	const uint32_t errors = RAMBLUR_ESR_AUTH_ERROR |
				RAMBLUR_ESR_VAULT_TXN_ERROR;
	paddr_t start = RAMBLUR_PIMEM_BASE;
	uint32_t version = 0;
	uint32_t esr = 0;
	uint64_t t = 0;
	int n = 0;

	COMPILE_TIME_ASSERT(CFG_QCOM_RAMBLUR_TA_WINDOW_ID > 0);
	COMPILE_TIME_ASSERT(CFG_QCOM_RAMBLUR_TA_WINDOW_ID < RAMBLUR_WINDOWS);
	COMPILE_TIME_ASSERT(IS_ALIGNED(TA_WIN_BASE, RAMBLUR_WIN_GRANULE));
	COMPILE_TIME_ASSERT(IS_ALIGNED(TA_WIN_SIZE, RAMBLUR_WIN_GRANULE));
	COMPILE_TIME_ASSERT(!(TA_WIN_SIZE & ~RAMBLUR_WIN_SIZE_MASK));

	ramblur_va = (vaddr_t)phys_to_virt(RAMBLUR_PIMEM_REG_BASE,
					   MEM_AREA_IO_SEC,
					   RAMBLUR_PIMEM_REG_SIZE);
	if (!ramblur_va)
		panic("Can't map Ramblur pIMEM");

	version = io_read32(ramblur_va + RAMBLUR_VERSION);
	if (RAMBLUR_VERSION_MAJOR(version) != 2)
		panic("Unsupported Ramblur pIMEM version");

	for (n = 0; n < window; n++)
		start += win_size(n);

	if (start != TA_WIN_BASE) {
		EMSG("pIMEM TA window at %#"PRIxPA", TA RAM at %#"PRIxPA,
		     start, (paddr_t)TA_WIN_BASE);
		panic();
	}

	for (n = window + 1; n < RAMBLUR_WINDOWS; n++)
		if (win_size(n))
			panic("pIMEM window above the TA window in use");

	check_window_unused(TA_WIN_BASE, TA_WIN_SIZE);

	esr = io_read32(ramblur_va + RAMBLUR_ESR);
	if (esr & errors)
		EMSG("pIMEM error status %#x before the TA window init",
		     (unsigned int)esr);

	t = barrier_read_counter_timer();
	init_window(window, TA_WIN_BASE, TA_WIN_SIZE);
	t = barrier_read_counter_timer() - t;
	if ((io_read32(ramblur_va + RAMBLUR_ESR) & ~esr) & errors)
		panic("pIMEM TA window init failed");

	DMSG("Ramblur pIMEM version %#x", (unsigned int)version);
	DMSG("Ramblur pIMEM TA window init: %"PRIu64" us",
	     t * 1000000 / read_cntfrq());

	return TEE_SUCCESS;
}
driver_init(qti_ramblur_pimem_init);
