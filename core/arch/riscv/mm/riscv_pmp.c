// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#include <assert.h>
#include <kernel/linker.h>
#include <mm/core_memprot.h>
#include <riscv_pmp.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/*
 * The regions kern.ld.S lays out, with the access the domain device tree has
 * to grant each one. @va and @base are filled in at runtime instead of here,
 * see riscv_pmp_core_regions().
 */
static const struct riscv_pmp_region core_regions[] = {
	[RISCV_PMP_CORE_REGION_TEXT] = {
		.order = CFG_RISCV_CORE_TEXT_ORDER,
		.perms = RISCV_PMP_R | RISCV_PMP_X,
		.name = "text",
	},
	[RISCV_PMP_CORE_REGION_RODATA] = {
		.order = CFG_RISCV_CORE_RODATA_ORDER,
		.perms = RISCV_PMP_R,
		.name = "rodata",
	},
	[RISCV_PMP_CORE_REGION_RWDATA] = {
		.order = CFG_RISCV_CORE_RWDATA_ORDER,
		.perms = RISCV_PMP_R | RISCV_PMP_W,
		.name = "data",
	},
};

static_assert(ARRAY_SIZE(core_regions) == RISCV_PMP_CORE_REGION_COUNT);

size_t riscv_pmp_core_regions(struct riscv_pmp_region *regions, size_t count)
{
	size_t n = 0;

	if (count < ARRAY_SIZE(core_regions))
		return ARRAY_SIZE(core_regions);

	memcpy(regions, core_regions, sizeof(core_regions));

	/*
	 * The __vcore_* symbols are absolute, so holding them in the array
	 * above would need a relative relocation to follow the ASLR offset,
	 * which the RISC-V linker no longer emits for absolute symbols.
	 * Reading them here keeps the access PC-relative. PMP matches
	 * physical addresses, so the bases are translated back.
	 */
	regions[RISCV_PMP_CORE_REGION_TEXT].va = VCORE_UNPG_RX_PA;
	regions[RISCV_PMP_CORE_REGION_RODATA].va = VCORE_UNPG_RO_PA;
	regions[RISCV_PMP_CORE_REGION_RWDATA].va = VCORE_UNPG_RW_PA;

	for (n = 0; n < ARRAY_SIZE(core_regions); n++)
		regions[n].base = virt_to_phys((void *)regions[n].va);

	return ARRAY_SIZE(core_regions);
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
