// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#include <kernel/linker.h>
#include <mm/core_memprot.h>
#include <riscv_pmp.h>
#include <stdint.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/* The permissions the domain device tree has to grant the trusted domain */
size_t riscv_pmp_core_regions(struct riscv_pmp_region *regions, size_t count)
{
	static const uint8_t order[RISCV_PMP_CORE_REGION_COUNT] = {
		CFG_RISCV_CORE_TEXT_ORDER,
		CFG_RISCV_CORE_RODATA_ORDER,
		CFG_RISCV_CORE_RWDATA_ORDER,
	};
	static const uint8_t perms[RISCV_PMP_CORE_REGION_COUNT] = {
		RISCV_PMP_R | RISCV_PMP_X,
		RISCV_PMP_R,
		RISCV_PMP_R | RISCV_PMP_W,
	};
	static const char * const name[RISCV_PMP_CORE_REGION_COUNT] = {
		"text", "rodata", "data",
	};
	/* Linker symbols are virtual here, PMP matches physical */
	const vaddr_t va[RISCV_PMP_CORE_REGION_COUNT] = {
		VCORE_UNPG_RX_PA, VCORE_UNPG_RO_PA, VCORE_UNPG_RW_PA,
	};
	size_t n = 0;

	if (count < RISCV_PMP_CORE_REGION_COUNT)
		return 0;

	for (n = 0; n < RISCV_PMP_CORE_REGION_COUNT; n++)
		regions[n] = (struct riscv_pmp_region){
			.base = virt_to_phys((void *)va[n]),
			.va = va[n],
			.order = order[n],
			.perms = perms[n],
			.name = name[n],
		};

	return RISCV_PMP_CORE_REGION_COUNT;
}

static void dump_region(const struct riscv_pmp_region *r)
{
	uint64_t base = r->base;

	if (!riscv_pmp_region_is_napot(r))
		EMSG("Core %s region is not NAPOT representable", r->name);

	IMSG("  %s base = <0x%"PRIx32" 0x%08"PRIx32">; order = <%u>; %c%c%c",
	     r->name, (uint32_t)(base >> 32), (uint32_t)base, r->order,
	     (r->perms & RISCV_PMP_R) ? 'r' : '-',
	     (r->perms & RISCV_PMP_W) ? 'w' : '-',
	     (r->perms & RISCV_PMP_X) ? 'x' : '-');
}

void riscv_pmp_dump_core_regions(void)
{
	struct riscv_pmp_region region[RISCV_PMP_CORE_REGION_COUNT] = { };
	size_t count = riscv_pmp_core_regions(region, ARRAY_SIZE(region));
	size_t n = 0;

	IMSG("Core PMP regions for the OpenSBI domain device tree:");

	for (n = 0; n < count; n++)
		dump_region(region + n);
}
