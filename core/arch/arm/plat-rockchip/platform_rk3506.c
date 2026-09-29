// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Owen O'Hehir
 *
 * RK3506B DDR-firewall (FW_DDR) and system-firewall (SGRF) setup.
 *
 * Code structure follows the upstream BSD-2 rk3399/rk3588/px30
 * platform_secure_*() implementations.
 *
 * platform_secure_init() opens the SGRF so the non-secure world can
 * reach its peripherals (notably the UART0 console); without it the
 * first NS UART0 access external-aborts after the hand-off to U-Boot.
 *
 * platform_secure_ddr_region(): with CFG_RK3506_TEE_HW_ISOLATE the
 * FW_DDR slot-0 region HW-isolates a low-DRAM TEE_RAM from the
 * non-secure Cortex-A7 (the firewall only covers low DRAM); otherwise
 * it opens DRAM and the TEE relies on the kernel-DT no-map reservation.
 */

#include <assert.h>
#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

/*
 * FW_DDR register offsets (relative to FIREWALL_DDR_BASE). The region
 * slots and the 0x7fff field encoding follow the BSD-2 OP-TEE rk3588
 * port; the per-master access regs and the control reg follow the
 * BSD-2 px30 port.
 */
#define FW_DDR_RGN(i)		((i) * 0x4)		/* region slots 0..7 */
#define FW_DDR_ACC(i)		(0x20 + ((i) * 0x4))	/* per-master, i=0..3 */
#define FW_DDR_ACC_X		0x30
#define FW_DDR_CON		0x40

#define FW_DDR_ACC_ALL		U(0xffffffff)
#define FW_DDR_ACC_X_NSMASK	U(0xff)

/*
 * FW_DDR region slot value (128 KB-granule, 15-bit fields):
 *	val = (base / 128K) | (((size / 128K) - 1) << 16), each field masked
 *	to 15 bits (the hardware 0x7fff field width).
 */
#define FW_DDR_RG_128K(base, size) \
	((((base) / SIZE_K(128)) & GENMASK_32(14, 0)) | \
	 (((((size) / SIZE_K(128)) - 1) & GENMASK_32(14, 0)) << 16))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE,
			FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_SYS_BASE,
			FIREWALL_SYS_SIZE);

/*
 * Open the SGRF gates to the non-secure world so it can reach UART0 and
 * the rest of the peripherals it owns.
 *
 * Slave-security CON block: Rockchip masked-write semantics - hi16 =
 * per-bit write-enable, lo16 = value; a slave's bit set under the write
 * mask = secure. SLAVE_ALL_NS (0xffff0000) enables all 16 bits to 0 =
 * all slaves non-secure - the public upstream idiom, identical to
 * plat-rk322x platform_secure_init().
 *
 * The two extra gates at +0x140/+0x144 (the secure_conf region, DT
 * secure_conf = <0xff210100> = base + 0x100) are opened all-ways; the
 * slave-CON config alone leaves UART0 inaccessible to NS on this
 * silicon, so they are required.
 */
#define SLAVE_ALL_NS		GENMASK_32(31, 16)
#define SGRF_GATE_OPEN_FULL	U(0xffffffff)

static const uint32_t rk3506_sgrf_slave_con[] = {
	0x020, 0x024, 0x028, 0x02c, 0x030, 0x034, 0x038, 0x03c,
	0x040, 0x044, 0x048, 0x04c,
};

static const uint32_t rk3506_sgrf_extra_open[] = { 0x140, 0x144 };

int platform_secure_init(void)
{
	vaddr_t fw = (vaddr_t)phys_to_virt_io(FIREWALL_SYS_BASE,
					      FIREWALL_SYS_SIZE);
	size_t i = 0;

	if (!fw)
		panic();

	MSG("rk3506 SGRF: opening all slaves non-secure (UART0 etc.)");

	for (i = 0; i < ARRAY_SIZE(rk3506_sgrf_slave_con); i++)
		io_write32(fw + rk3506_sgrf_slave_con[i], SLAVE_ALL_NS);

	for (i = 0; i < ARRAY_SIZE(rk3506_sgrf_extra_open); i++)
		io_write32(fw + rk3506_sgrf_extra_open[i], SGRF_GATE_OPEN_FULL);

	return 0;
}

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
					      FIREWALL_DDR_SIZE);
	unsigned int i = 0;

	if (!fw)
		panic();

	/*
	 * The generic rockchip caller requests region slot 1 (platform.c).
	 * This port instead programs a single low-DRAM region in FW_DDR
	 * slot 0 (see the HW-isolate note below) and does not use the
	 * caller's slot selector. Assert the expected request so an
	 * unexpected caller is caught in debug builds.
	 */
	assert(rgn == 1);

	/*
	 * Start from a known-empty firewall. On RK3506 the enable register
	 * (FW_DDR_CON) is re-derived from the region *definitions* on every
	 * access-permit write below, so clearing the enable alone is not
	 * enough: a region left defined+enabled by the upstream DDR-init
	 * stage (some boards hand over with region 0 covering all of DRAM)
	 * would be re-armed by the master-permit writes and lock the normal
	 * world out of DRAM. Clear the region definitions too so the result
	 * is independent of the prior stage's firewall state.
	 */
	for (i = 0; i < 8; i++)
		io_write32(fw + FW_DDR_RGN(i), 0);
	io_write32(fw + FW_DDR_CON, 0);

	if (IS_ENABLED(CFG_RK3506_TEE_HW_ISOLATE)) {
		/*
		 * HW-isolate the TEE region.
		 *
		 * The FW_DDR only gates the NS Cortex-A7 for regions in low
		 * DRAM; a high placement such as 0x18000000 is outside its
		 * coverage and is never enforced. This path therefore keeps
		 * TEE_RAM low (CFG_TZDRAM_START, near the bottom of DRAM but
		 * clear of PA 0, which the boot chain uses) and secures it via
		 * slot 0. Latch RGN -> CON before opening the masters (an
		 * unlatched region is clobbered by a master write); NS reads of
		 * the protected window then abort.
		 *
		 * The slot encodes base and size in 128 KB units (size as
		 * size/128K - 1); see FW_DDR_RG_128K(). This is an opt-in path
		 * that must be paired with a boot loader whose non-secure
		 * memory map sits clear of the protected low region.
		 */
		assert(sz);
		assert(st / SIZE_M(1) == 0); /* low-DRAM coverage */
		MSG("rk3506 FW_DDR: HW-isolating TEE [0x%" PRIxPA
		    ",0x%" PRIxPA ")", st, st + sz);
		io_write32(fw + FW_DDR_RGN(0), FW_DDR_RG_128K(st, sz));
		io_setbits32(fw + FW_DDR_CON, BIT(0));
	} else {
		MSG("rk3506 FW_DDR: opening NS DRAM (TEE 0x%" PRIxPA
		    "-0x%" PRIxPA ")", st, st + sz);
	}

	/*
	 * Permit all masters / NS access across the rest of DRAM so the NS
	 * world runs; any latched secure region above overrides this.
	 */
	for (i = 0; i < 4; i++)
		io_write32(fw + FW_DDR_ACC(i), FW_DDR_ACC_ALL);

	io_setbits32(fw + FW_DDR_ACC_X, FW_DDR_ACC_X_NSMASK);

	return 0;
}
