// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2019, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2026, Owen O'Hehir
 *
 * RK3506B PSCI back end.
 *
 * Secondary-core release follows the Rockchip "cpuson" model, ported in
 * structure from the BSD-3-Clause TF-A plat/rockchip pmusram pen (rk3288
 * is the ARMv7 analogue). The BootROM parks the secondaries in a WFE
 * spin polling a shared SRAM mailbox at IRAM_BASE:
 *
 *	while (*(uint32_t *)(IRAM_BASE + 0x04) != 0xdeadbeaf)
 *		wfe();
 *	pc = *(uint32_t *)(IRAM_BASE + 0x08);
 *
 * We install a small position-independent pen (pen_rk3506.S) at a
 * 64 KiB-aligned SRAM slot and point the mailbox entry word at it. The
 * first psci_cpu_on() releases all parked secondaries into the pen; each
 * core then WFE-polls its own per-core slot and only long-jumps into
 * OP-TEE (TEE_LOAD_ADDR) once psci_cpu_on(core) has set slot[core]. From
 * there the generic CFG_BOOT_SECONDARY_REQUEST path bounces it to the
 * non-secure entry. No PMU power-on or CRU soft-reset is needed: the
 * secondaries are already powered and running the BootROM spin.
 *
 * The cpuson pen structure is from BSD-3 TF-A plat/rockchip.
 */

#include <arm.h>
#include <assert.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>

#include "pen_rk3506.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, IRAM_BASE, IRAM_SIZE);

/*
 * Software online-core tracking for psci_affinity_info(). Mutated by
 * psci_cpu_on() (boot CPU) and psci_cpu_off() (the core going down), so
 * the read-modify-writes are serialised by a spinlock.
 */
static uint32_t online_cores = BIT(0);
static unsigned int online_cores_lock = SPINLOCK_UNLOCK;

static vaddr_t iram_va(void)
{
	return (vaddr_t)phys_to_virt_io(IRAM_BASE, IRAM_SIZE);
}

/*
 * Install the pen into IRAM. Runs once on the boot CPU (MMU up) before
 * any PSCI CPU_ON. The blob is copied verbatim and its single trailing
 * data word is patched with the per-core slot-table PA; the pen
 * WFE-polls slot[core] and psci_cpu_on(core) sets it to release a core.
 */
static TEE_Result rk3506_pen_install(void)
{
	vaddr_t iram = iram_va();
	size_t len = (size_t)(rk3506_pen_end - rk3506_pen_start);
	vaddr_t pen = iram + (RK3506_PEN_PA - IRAM_BASE);
	vaddr_t slots = iram + (RK3506_SLOTS_PA - IRAM_BASE);
	size_t i = 0;

	if (!iram)
		panic("rk3506: IRAM not mapped");
	assert(len >= 8 && len <= 256 && !(len % 4));

	/*
	 * IRAM is mapped MEM_AREA_IO_SEC, i.e. Device-nGnRE. memcpy()/memset()
	 * may emit unaligned or multi-word (LDM/STM) accesses, which to Device
	 * memory are CONSTRAINED UNPREDICTABLE on ARMv7-A; copy/clear with
	 * explicit aligned word stores instead. The pen blob is word-aligned
	 * (.balign 8) and a whole number of words.
	 */
	for (i = 0; i < len; i += 4)
		io_write32(pen + i, get_le32(rk3506_pen_start + i));
	io_write32(pen + len - 4, RK3506_SLOTS_PA);

	/* Clear the per-core gate slots (0 = "not yet released"). */
	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
		io_write32(slots + i * 4, 0);

	/* Device-mapped stores reach SRAM directly; no cache maintenance. */
	dsb();

	DMSG("rk3506: secondary-core pen installed at 0x%x (%zu bytes)",
	     RK3506_PEN_PA, len);
	return TEE_SUCCESS;
}

service_init_late(rk3506_pen_install);

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_CPU_ON:
	case PSCI_CPU_OFF:
	case PSCI_AFFINITY_INFO:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

int psci_cpu_on(uint32_t core_idx, uint32_t entry, uint32_t context_id)
{
	uint32_t core = core_idx & MPIDR_CPU_MASK;
	vaddr_t iram = iram_va();

	if (core == 0 || core >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;
	if (!iram)
		return PSCI_RET_INTERNAL_FAILURE;

	/*
	 * Reject a redundant CPU_ON for an already-online core before
	 * touching any shared HW. Claim the core under the lock so a
	 * concurrent call for the same core loses the race cleanly.
	 */
	cpu_spin_lock(&online_cores_lock);
	if (online_cores & BIT(core)) {
		cpu_spin_unlock(&online_cores_lock);
		return PSCI_RET_ALREADY_ON;
	}
	online_cores |= BIT(core);
	cpu_spin_unlock(&online_cores_lock);

	/* Generic OP-TEE secondary path: where to bounce to NS. */
	boot_set_core_ns_entry(core, entry, context_id);

	/*
	 * Release this core: set slot[core] so the pen jumps it into
	 * OP-TEE, (re-)arm the shared BootROM mailbox, then SEV to wake
	 * both the BootROM WFE (first call) and the pen's per-core WFE.
	 * Runtime + SRAM-only, so it cannot disturb the non-secure boot.
	 */
	io_write32(iram + (RK3506_SLOTS_PA - IRAM_BASE) + core * 4,
		   TEE_LOAD_ADDR);
	dsb();
	io_write32(iram + (RK3506_BROM_ENTRY_PA - IRAM_BASE), RK3506_PEN_PA);
	io_write32(iram + (RK3506_BROM_FLAG_PA - IRAM_BASE), RK3506_BROM_MAGIC);
	dsb();
	sev();
	dsb();

	DMSG("core %" PRIu32 " released (ns_entry 0x%" PRIx32 ")", core, entry);

	return PSCI_RET_SUCCESS;
}

int psci_cpu_off(void)
{
	uint32_t core = get_core_pos();
	vaddr_t iram = iram_va();
	void (*cpu_down)(vaddr_t pen);
	paddr_t down_pa = 0;

	if (core == 0 || core >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;
	if (!iram)
		return PSCI_RET_INTERNAL_FAILURE;

	/*
	 * Resolve the physical entry of the down-path now, while the MMU and
	 * caches are still up. rk3506_cpu_down() disables the MMU, so it must
	 * execute where VA==PA: it lives in the .identity_map region, which the
	 * core page tables map flat, and entering it via that physical address
	 * keeps the PC valid across the MMU disable under CFG_CORE_ASLR.
	 */
	down_pa = virt_to_phys((void *)(vaddr_t)rk3506_cpu_down);
	if (!down_pa)
		return PSCI_RET_INTERNAL_FAILURE;
	cpu_down = (void (*)(vaddr_t))(vaddr_t)down_pa;

	DMSG("core %" PRIu32, core);

	/*
	 * Clear our gate slot so that, once the core re-enters the pen, it
	 * parks in the pen's WFE loop instead of jumping back into OP-TEE. The
	 * slot is in Device-mapped IRAM, so the store reaches SRAM directly.
	 */
	io_write32(iram + (RK3506_SLOTS_PA - IRAM_BASE) + core * 4, 0);
	dsb();

	cpu_spin_lock(&online_cores_lock);
	online_cores &= ~BIT(core);
	cpu_spin_unlock(&online_cores_lock);

	/* Clean+disable the D-cache and exit SMP coherency, then re-park. */
	psci_armv7_cpu_off();
	thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_down(RK3506_PEN_PA);

	return PSCI_RET_INTERNAL_FAILURE;
}

int psci_affinity_info(uint32_t affinity,
		       uint32_t lowest_affinity_level __unused)
{
	uint32_t core = affinity & MPIDR_CPU_MASK;
	uint32_t on = 0;

	if (core >= CFG_TEE_CORE_NB_CORE)
		return PSCI_AFFINITY_LEVEL_OFF;

	cpu_spin_lock(&online_cores_lock);
	on = online_cores & BIT(core);
	cpu_spin_unlock(&online_cores_lock);

	return on ? PSCI_AFFINITY_LEVEL_ON : PSCI_AFFINITY_LEVEL_OFF;
}
