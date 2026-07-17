// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "lpass.h"

/*
 * QDSP6 boot registers, relative to the LPASS subsystem base. The PUB block
 * holds the reset/boot FSM registers; the MCC block holds the EVB select. The
 * Q6 PLL and core RCG are configured earlier by the clock driver (lpass_setup).
 */
#define LPASS_PUB_OFFSET		0x00400000
#define LPASS_MCC_OFFSET		0x008d0000

#define LPASS_QDSP6SS_RST_EVB		(LPASS_PUB_OFFSET + 0x10)
#define LPASS_QDSP6SS_BOOT_CORE_START	(LPASS_PUB_OFFSET + 0x400)
#define LPASS_QDSP6SS_BOOT_CMD		(LPASS_PUB_OFFSET + 0x404)
#define LPASS_QDSP6SS_BOOT_STATUS	(LPASS_PUB_OFFSET + 0x408)

#define LPASS_EFUSE_Q6SS_EVB_SEL	(LPASS_MCC_OFFSET + 0xb000)

#define BOOT_FSM_TIMEOUT	10000

/*
 * LPASS / ADSP (QDSP6) IOMMU device-memory resource table. Translated verbatim
 * from the reference TZ SMMU static config (adsp_q6_elf[] in
 * ssg/securemsm/accesscontrol/cfg/lemans/tz/ACSmmuStaticConfig.c). Regions are
 * identity-mapped (da == pa); flags follow the AC_PERM_R / AC_PERM_W bits.
 */
static const struct fw_rsc_devmem lpass_mem_res[] = {
	{ .name = "gcc_gpll0_3", .flags = IOMMU_READ,
		.da = 0x110000, .pa = 0x110000, .len = 0x4000, },
	{ .name = "gcc_gpll6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x123000, .pa = 0x123000, .len = 0x1000, },
	{ .name = "gcc_qupv3_wrap1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x124000, .pa = 0x124000, .len = 0x3000, },
	{ .name = "gcc_qupv3_wrap0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x127000, .pa = 0x127000, .len = 0x2000, },
	{ .name = "gcc_gpll7_9", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x12a000, .pa = 0x12a000, .len = 0x3000, },
	{ .name = "gcc_qupv3_wrap2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x12e000, .pa = 0x12e000, .len = 0x1000, },
	{ .name = "gcc_gpll10", .flags = IOMMU_READ,
		.da = 0x12f000, .pa = 0x12f000, .len = 0x1000, },
	{ .name = "gcc_boot_rom_ahb", .flags = IOMMU_READ,
		.da = 0x144000, .pa = 0x144000, .len = 0x1000, },
	{ .name = "gcc_boot_rom", .flags = IOMMU_READ,
		.da = 0x148000, .pa = 0x148000, .len = 0x1000, },
	{ .name = "gcc_lpass_cfg0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x149000, .pa = 0x149000, .len = 0xe000, },
	{ .name = "gcc_lpass_cbcr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x157000, .pa = 0x157000, .len = 0x1000, },
	{ .name = "gcc_lpass_cfg1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x158000, .pa = 0x158000, .len = 0xd000, },
	{ .name = "gcc_lpass_dsp_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x165000, .pa = 0x165000, .len = 0x1000, },
	{ .name = "gcc_clk_frq_measure", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x172000, .pa = 0x172000, .len = 0x1000, },
	{ .name = "gcc_pll_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x173000, .pa = 0x173000, .len = 0x8000, },
	{ .name = "gcc_pcie4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x17b000, .pa = 0x17b000, .len = 0x2000, },
	{ .name = "gcc_pcie_phy", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x17f000, .pa = 0x17f000, .len = 0x1000, },
	{ .name = "gcc_gpll5", .flags = IOMMU_READ,
		.da = 0x184000, .pa = 0x184000, .len = 0x1000, },
	{ .name = "gcc_gpll4", .flags = IOMMU_READ,
		.da = 0x186000, .pa = 0x186000, .len = 0x1000, },
	{ .name = "gcc_pcie1_tunnel", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x19c000, .pa = 0x19c000, .len = 0x3000, },
	{ .name = "gcc_pcie1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x19f000, .pa = 0x19f000, .len = 0xe000, },
	{ .name = "gcc_pcie2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1ad000, .pa = 0x1ad000, .len = 0x2000, },
	{ .name = "gcc_pcie3a", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b0000, .pa = 0x1b0000, .len = 0x1000, },
	{ .name = "gcc_pcie3b", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b2000, .pa = 0x1b2000, .len = 0x1000, },
	{ .name = "gcc_pcie0_tunnel", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b4000, .pa = 0x1b4000, .len = 0x1000, },
	{ .name = "gcc_pcie_throttle", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b6000, .pa = 0x1b6000, .len = 0x1000, },
	{ .name = "gcc_pcie_rscc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1be000, .pa = 0x1be000, .len = 0x1000, },
	{ .name = "gcc_pcie_rscc_seq", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1bf000, .pa = 0x1bf000, .len = 0x10000, },
	{ .name = "gcc_aggre_pcie", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1cf000, .pa = 0x1cf000, .len = 0x1000, },
	{ .name = "lpass_ipc_mproc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x403000, .pa = 0x403000, .len = 0x1000, },
	{ .name = "lpass_ipc_computel0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x443000, .pa = 0x443000, .len = 0x1000, },
	{ .name = "lpass_ipc_computel1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x483000, .pa = 0x483000, .len = 0x1000, },
	{ .name = "lpass_ipc_periph", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4c3000, .pa = 0x4c3000, .len = 0x1000, },
	{ .name = "ipc_mode", .flags = IOMMU_READ,
		.da = 0x4fc000, .pa = 0x4fc000, .len = 0x1000, },
	{ .name = "oem_fuses", .flags = IOMMU_READ,
		.da = 0x780000, .pa = 0x780000, .len = 0x7000, },
	{ .name = "hwkm_prng_cm", .flags = IOMMU_READ,
		.da = 0x10d0000, .pa = 0x10d0000, .len = 0x1000, },
	{ .name = "rng", .flags = IOMMU_READ,
		.da = 0x10d4000, .pa = 0x10d4000, .len = 0x1000, },
	{ .name = "tcsr_dbg0", .flags = IOMMU_READ,
		.da = 0x1dc4000, .pa = 0x1dc4000, .len = 0x1000, },
	{ .name = "tcsr_dbg1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1dc5000, .pa = 0x1dc5000, .len = 0x1000, },
	{ .name = "tcsr_dbg2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1dc8000, .pa = 0x1dc8000, .len = 0x1000, },
	{ .name = "tcsr_dbg3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1dfa000, .pa = 0x1dfa000, .len = 0x1000, },
	{ .name = "tcsr_dbg4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1dfd000, .pa = 0x1dfd000, .len = 0x1000, },
	{ .name = "hw_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1f40000, .pa = 0x1f40000, .len = 0x40000, },
	{ .name = "tcsr_ro", .flags = IOMMU_READ,
		.da = 0x1fc0000, .pa = 0x1fc0000, .len = 0x29000, },
	{ .name = "tcsr_timeout_intr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1fe9000, .pa = 0x1fe9000, .len = 0x1000, },
	{ .name = "tcsr_ro1", .flags = IOMMU_READ,
		.da = 0x1fea000, .pa = 0x1fea000, .len = 0x1000, },
	{ .name = "tcsr_ro2", .flags = IOMMU_READ,
		.da = 0x1feb000, .pa = 0x1feb000, .len = 0x1000, },
	{ .name = "tcsr_ro3", .flags = IOMMU_READ,
		.da = 0x1fec000, .pa = 0x1fec000, .len = 0x4000, },
	{ .name = "lpass_ag_noc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3c41000, .pa = 0x3c41000, .len = 0x3000, },
	{ .name = "lpass_ag_noc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3c4f000, .pa = 0x3c4f000, .len = 0x1000, },
	{ .name = "lpass_core0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4001000, .pa = 0x4001000, .len = 0x1000, },
	{ .name = "lpass_core1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4002000, .pa = 0x4002000, .len = 0x1000, },
	{ .name = "lpass_core2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4041000, .pa = 0x4041000, .len = 0x1000, },
	{ .name = "lpass_core3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4042000, .pa = 0x4042000, .len = 0x1000, },
	{ .name = "lpass_core4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4043000, .pa = 0x4043000, .len = 0x1000, },
	{ .name = "lpass_core5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4045000, .pa = 0x4045000, .len = 0x1000, },
	{ .name = "lpass_core6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4046000, .pa = 0x4046000, .len = 0x1000, },
	{ .name = "lpass_core7", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x404e000, .pa = 0x404e000, .len = 0x1000, },
	{ .name = "lpass_core8", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x404f000, .pa = 0x404f000, .len = 0x1000, },
	{ .name = "lpass_qdss0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4b04000, .pa = 0x4b04000, .len = 0x1000, },
	{ .name = "lpass_qdss1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4b05000, .pa = 0x4b05000, .len = 0x1000, },
	{ .name = "lpass_qdss2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4b11000, .pa = 0x4b11000, .len = 0x1000, },
	{ .name = "lpass_island_dbg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4b40000, .pa = 0x4b40000, .len = 0x20000, },
	{ .name = "ddr_llc_info", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9080000, .pa = 0x9080000, .len = 0x1000, },
	{ .name = "llcc_trp0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9200000, .pa = 0x9200000, .len = 0x28000, },
	{ .name = "llcc_trp1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9300000, .pa = 0x9300000, .len = 0x28000, },
	{ .name = "llcc_trp2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9400000, .pa = 0x9400000, .len = 0x28000, },
	{ .name = "llcc_trp3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9500000, .pa = 0x9500000, .len = 0x28000, },
	{ .name = "llcc_trp4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9600000, .pa = 0x9600000, .len = 0x28000, },
	{ .name = "llcc_trp5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9700000, .pa = 0x9700000, .len = 0x28000, },
	{ .name = "pdc_audio", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb250000, .pa = 0xb250000, .len = 0x10000, },
	{ .name = "pdc_audio1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb450000, .pa = 0xb450000, .len = 0x10000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ,
		.da = 0xbbf0000, .pa = 0xbbf0000, .len = 0x2000, },
	{ .name = "mpm", .flags = IOMMU_READ,
		.da = 0xc210000, .pa = 0xc210000, .len = 0x80000, },
	{ .name = "rpmh_drv_lpass", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc340000, .pa = 0xc340000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv0", .flags = IOMMU_READ,
		.da = 0xc370000, .pa = 0xc370000, .len = 0x1000, },
	{ .name = "rpmh_drv8_aop", .flags = IOMMU_READ,
		.da = 0xc380000, .pa = 0xc380000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv1", .flags = IOMMU_READ,
		.da = 0xc390000, .pa = 0xc390000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv2", .flags = IOMMU_READ,
		.da = 0xc3a0000, .pa = 0xc3a0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv3", .flags = IOMMU_READ,
		.da = 0xc3b0000, .pa = 0xc3b0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv4", .flags = IOMMU_READ,
		.da = 0xc3c0000, .pa = 0xc3c0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv5", .flags = IOMMU_READ,
		.da = 0xc3d0000, .pa = 0xc3d0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc3e0000, .pa = 0xc3e0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv7", .flags = IOMMU_READ,
		.da = 0xc3f0000, .pa = 0xc3f0000, .len = 0x1000, },
	{ .name = "pmic_arb_master", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc400000, .pa = 0xc400000, .len = 0x30000, },
	{ .name = "pmic_arb", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc440000, .pa = 0xc440000, .len = 0x10000, },
	{ .name = "pmic_arb_mgpi", .flags = IOMMU_READ,
		.da = 0xc460000, .pa = 0xc460000, .len = 0x81000, },
	{ .name = "pmic_obs", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xe600000, .pa = 0xe600000, .len = 0x100000, },
	{ .name = "spmi_pic", .flags = IOMMU_READ,
		.da = 0xe700000, .pa = 0xe700000, .len = 0xa0000, },
	{ .name = "tlmm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xf000000, .pa = 0xf000000, .len = 0x1000000, },
	{ .name = "sys_imem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x146d8000, .pa = 0x146d8000, .len = 0x1000, },
	{ .name = "stm_trace", .flags = IOMMU_WRITE,
		.da = 0x16000000, .pa = 0x16000000, .len = 0x1000000, },
	{ .name = "aop_cmd_db", .flags = IOMMU_READ,
		.da = 0x90860000, .pa = 0x90860000, .len = 0x20000, },
	/* SMEM (smem@90900000, 2 MB) holds the GLINK FIFOs the DSP must
	 * read/write to talk to the apps processor. Without this mapping the
	 * DSP takes a translation fault on its first SMEM access (e.g. iova
	 * 0x90aff330) -> mmufault/watchdog and never reaches running.
	 */
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x90900000, .pa = 0x90900000, .len = 0x200000, },
};

DEFINE_RESOURCE_TABLE(LPASS, ARRAY_SIZE(lpass_mem_res));

static TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timeout = timeout_init_us(BOOT_FSM_TIMEOUT);

	if (!base)
		return TEE_ERROR_GENERIC;

	/*
	 * Program the firmware entry address and select the programmed EVB.
	 * The Q6 PLL and core RCG are already configured by lpass_setup() in
	 * the clock driver, mirroring Setup_LPASSProcessor +
	 * lpass_program_boot_addr in the reference TZ.
	 */
	io_write32(base + LPASS_QDSP6SS_RST_EVB, data->fw_base >> 4);
	io_write32(base + LPASS_EFUSE_Q6SS_EVB_SEL, 0);
	dsb();

	/* De-assert stop-core, then trigger the boot FSM. */
	io_setbits32(base + LPASS_QDSP6SS_BOOT_CORE_START, BIT(0));
	io_write32(base + LPASS_QDSP6SS_BOOT_CMD, 0x1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(base + LPASS_QDSP6SS_BOOT_STATUS) & BIT(0))
			return TEE_SUCCESS;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result lpass_get_resource_table(struct resource_table *rt,
					   size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = LPASS_NUM_MEM_RESOURCES,
		.offset[LPASS_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   lpass_mem_res,
			   LPASS_RESOURCE_TABLE_HEADER_SIZE,
			   LPASS_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops lpass_ops = {
	.fw_start = lpass_fw_start,
	.fw_shutdown = lpass_fw_shutdown,
	.get_resource_table = lpass_get_resource_table,
};
