// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Owen O'Hehir
 *
 * RV1106G3 system-firewall (SGRF) and DDR-firewall (FW_DDR) setup. The code
 * follows the upstream plat-rk322x platform_secure_init() and the plat-rk3588
 * FW_DDR block.
 *
 * A prior boot stage opens every SGRF slave to the non-secure world before
 * OP-TEE runs, so the NS world can reach its peripherals (the UART2 console
 * etc.) after the hand-off. platform_secure_init() re-asserts that all-NS
 * state so OP-TEE owns the gate configuration explicitly; at v1 OP-TEE keeps
 * no peripheral secure (software crypto, no secure CE).
 *
 * platform_secure_ddr_region() isolates TZDRAM via the FW_DDR block, the same
 * IP as the upstream plat-rk3588 (RGN(i) = i*4, CON = 0xf0; RG_MAP_SECURE packs
 * (top-1) into [30:16] and base into [14:0], both in MB), but without rk3588's
 * DSU channels (RV1106 is single core, no DSU).
 */

#include <assert.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, PERI_SGRF_BASE, PERI_SGRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CORE_SGRF_BASE, CORE_SGRF_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, FW_DDR_BASE, FW_DDR_SIZE);

/* SGRF firewall control registers (FIREWALL_CON0..4) */
#define SGRF_FIREWALL_CON(n)	(0x20 + (n) * 4)
#define SGRF_FIREWALL_CON_NUM	5

/*
 * Rockchip masked write: bits 31:16 are the per-bit write-enable, bits 15:0
 * the value. Driving all 16 slave bits to 0 under the write mask marks every
 * slave non-secure - the same idiom as plat-rk322x SLAVE_ALL_NS.
 */
#define SLAVE_ALL_NS		GENMASK_32(31, 16)

int platform_secure_init(void)
{
	vaddr_t peri = (vaddr_t)phys_to_virt_io(PERI_SGRF_BASE, PERI_SGRF_SIZE);
	vaddr_t core = (vaddr_t)phys_to_virt_io(CORE_SGRF_BASE, CORE_SGRF_SIZE);
	unsigned int n = 0;

	if (!peri || !core)
		panic();

	for (n = 0; n < SGRF_FIREWALL_CON_NUM; n++) {
		io_write32(peri + SGRF_FIREWALL_CON(n), SLAVE_ALL_NS);
		io_write32(core + SGRF_FIREWALL_CON(n), SLAVE_ALL_NS);
	}

	return 0;
}

/*
 * FW_DDR region/enable layout, the same IP as the upstream plat-rk3588 FW_DDR
 * block (RV1106 has no DSU channels).
 */
#define FW_DDR_RGN(i)		((i) * 0x4)
#define FW_DDR_CON		0xf0
#define FW_DDR_RGN_NUM		16
#define FW_DDR_RGN_MASK		GENMASK_32(14, 0)
#define RG_MAP_SECURE(top, base) \
	(SHIFT_U32(((top) - 1) & FW_DDR_RGN_MASK, 16) | \
	 ((base) & FW_DDR_RGN_MASK))

/*
 * FW_DDR per-master access-control bank (MST0..MST11 at 0x40 + i*4). These
 * registers permit masters to reach DRAM; a latched secure region (RGN + CON)
 * overrides them for non-secure transactions, so permitting all masters lets
 * the NS world run while the NS Cortex-A7 still aborts on the secure window.
 * (On the ARMv8 rk3506/rk3588 the CPU is additionally gated by the DSU
 * firewall, which a single-A7 RV1106 lacks.)
 *
 * Permit every master fully; masters are 16 or 32 permit bits wide.
 */
#define FW_DDR_MST(i)		(0x40 + (i) * 0x4)

static void rv1106_fw_ddr_permit_masters(vaddr_t fw_ddr)
{
	static const uint32_t mst[] = {
		GENMASK_32(15, 0), GENMASK_32(15, 0), GENMASK_32(15, 0),
		GENMASK_32(31, 0), GENMASK_32(31, 0), GENMASK_32(31, 0),
		GENMASK_32(31, 0), GENMASK_32(31, 0), GENMASK_32(31, 0),
		GENMASK_32(15, 0), GENMASK_32(15, 0), GENMASK_32(31, 0),
	};
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(mst); i++)
		io_write32(fw_ddr + FW_DDR_MST(i), mst[i]);
}

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_ddr = (vaddr_t)phys_to_virt_io(FW_DDR_BASE, FW_DDR_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);

	if (!fw_ddr)
		panic();

	assert(rgn >= 0 && rgn < FW_DDR_RGN_NUM);
	assert(st < ed);
	/* FW_DDR regions are 1 MB-granular */
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%"PRIxPA"-0x%"PRIxPA, rgn, st, ed);

	if (IS_ENABLED(CFG_RV1106_TEE_HW_ISOLATE)) {
		unsigned int i = 0;

		/*
		 * Start from an empty firewall: a prior boot stage may hand
		 * over with a region already defined and enabled (e.g. region
		 * 0 covering all of DRAM). Once the master-permit writes below
		 * arm the firewall, such an inherited region would lock the NS
		 * world out of its own DRAM, so clear every region definition
		 * and the enable register first.
		 */
		for (i = 0; i < FW_DDR_RGN_NUM; i++)
			io_write32(fw_ddr + FW_DDR_RGN(i), 0);
		io_write32(fw_ddr + FW_DDR_CON, 0);
	}

	/* Define the secure DDR window, then latch it (before the masters) */
	io_write32(fw_ddr + FW_DDR_RGN(rgn), RG_MAP_SECURE(ed_mb, st_mb));
	io_setbits32(fw_ddr + FW_DDR_CON, BIT(rgn));

	if (IS_ENABLED(CFG_RV1106_TEE_HW_ISOLATE)) {
		/*
		 * Permit all masters across DRAM; the latched secure region
		 * above overrides for NS, so the NS A7 keeps its own DRAM but
		 * aborts on the secure window.
		 */
		rv1106_fw_ddr_permit_masters(fw_ddr);
	}

	return 0;
}
