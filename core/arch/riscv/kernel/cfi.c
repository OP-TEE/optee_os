// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */

#include <config.h>
#include <encoding.h>
#include <kernel/cfi.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <riscv.h>
#include <trace.h>

/* Set by the primary hart, every secondary must agree */
static bool lp_available;

/*
 * senvcfg.LPE is WPRI on a hart without Zicfilp: writes are ignored and
 * it reads as zero. Write it and read it back to learn whether landing
 * pads can be enforced for user mode at all. The bit is left clear, it
 * is set per user context by core_mmu_set_user_map().
 */
static bool probe_landing_pads(void)
{
	bool available = false;

	if (!IS_ENABLED(CFG_TA_ZICFILP))
		return false;

	set_csr(CSR_SENVCFG, CSR_SENVCFG_LPE);
	available = read_csr(CSR_SENVCFG) & CSR_SENVCFG_LPE;
	clear_csr(CSR_SENVCFG, CSR_SENVCFG_LPE);

	return available;
}

void cfi_init_hart(void)
{
	bool lp = probe_landing_pads();

	if (get_core_pos() == 0) {
		lp_available = lp;
		if (IS_ENABLED(CFG_TA_ZICFILP))
			IMSG("Zicfilp landing pads for user mode: %s",
			     lp ? "enabled" : "not available");
	} else if (lp != lp_available) {
		EMSG("Zicfilp availability differs between harts");
		panic();
	}
}
