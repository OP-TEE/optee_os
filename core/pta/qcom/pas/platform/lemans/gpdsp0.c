// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "gpdsp0.h"

#define GPDSP_QDSP6SS_RST_EVB		0x00c00010
#define GPDSP_QDSP6SS_BOOT_CORE_START	0x00c00400
#define GPDSP_QDSP6SS_BOOT_CMD		0x00c00404
#define GPDSP_QDSP6SS_BOOT_STATUS	0x00c00408

static const struct fw_rsc_devmem turing_mem_res[] = {
	{ .name = "gcc_gpll0_3", .flags = IOMMU_READ,
		.da = 0x110000, .pa = 0x110000, .len = 0x4000, },
	{ .name = "gcc_gpll6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x123000, .pa = 0x123000, .len = 0x1000, },
	{ .name = "gcc_qupv3_wrap1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x124000, .pa = 0x124000, .len = 0x3000, },
	{ .name = "gcc_qupv3_wrap0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x127000, .pa = 0x127000, .len = 0x3000, },
	{ .name = "gcc_gpll7_9", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x12a000, .pa = 0x12a000, .len = 0x3000, },
	{ .name = "gcc_qupv3_wrap2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x12e000, .pa = 0x12e000, .len = 0x1000, },
	{ .name = "gcc_gpll10", .flags = IOMMU_READ,
		.da = 0x12f000, .pa = 0x12f000, .len = 0x1000, },
	{ .name = "gcc_boot_rom", .flags = IOMMU_READ,
		.da = 0x144000, .pa = 0x144000, .len = 0x1000, },
	{ .name = "gcc_boot_rom_ahb", .flags = IOMMU_READ,
		.da = 0x148000, .pa = 0x148000, .len = 0x1000, },
	{ .name = "gcc_gpdsp0_gdscr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x155000, .pa = 0x155000, .len = 0x1000, },
	{ .name = "gcc_gpdsp0_pll_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x156000, .pa = 0x156000, .len = 0x15000, },
	{ .name = "gcc_gpdsp_dsp_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x16b000, .pa = 0x16b000, .len = 0x1000, },
	{ .name = "gcc_clk_frq_measure", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x172000, .pa = 0x172000, .len = 0x1000, },
	{ .name = "gcc_gpll5", .flags = IOMMU_READ,
		.da = 0x184000, .pa = 0x184000, .len = 0x1000, },
	{ .name = "gcc_gpll4", .flags = IOMMU_READ,
		.da = 0x186000, .pa = 0x186000, .len = 0x1000, },
	{ .name = "gcc_gpdsp0_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1c4000, .pa = 0x1c4000, .len = 0x1000, },
	{ .name = "gcc_gpdsp1_gdscr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1cc000, .pa = 0x1cc000, .len = 0x1000, },
	{ .name = "mproc_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x406000, .pa = 0x406000, .len = 0x1000, },
	{ .name = "mproc_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x412000, .pa = 0x412000, .len = 0x1000, },
	{ .name = "mproc_ipc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x41f000, .pa = 0x41f000, .len = 0x1000, },
	{ .name = "computel0_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x446000, .pa = 0x446000, .len = 0x1000, },
	{ .name = "computel0_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x452000, .pa = 0x452000, .len = 0x1000, },
	{ .name = "computel0_ipc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x45f000, .pa = 0x45f000, .len = 0x1000, },
	{ .name = "computel1_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x486000, .pa = 0x486000, .len = 0x1000, },
	{ .name = "computel1_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x492000, .pa = 0x492000, .len = 0x1000, },
	{ .name = "computel1_ipc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x49f000, .pa = 0x49f000, .len = 0x1000, },
	{ .name = "periph_ipc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4d2000, .pa = 0x4d2000, .len = 0x1000, },
	{ .name = "periph_ipc2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4df000, .pa = 0x4df000, .len = 0x1000, },
	{ .name = "ipc_mode", .flags = IOMMU_READ,
		.da = 0x4fc000, .pa = 0x4fc000, .len = 0x1000, },
	{ .name = "oem_fuses", .flags = IOMMU_READ,
		.da = 0x780000, .pa = 0x780000, .len = 0x10000, },
	{ .name = "hwkm_prng_cm", .flags = IOMMU_READ,
		.da = 0x10d0000, .pa = 0x10d0000, .len = 0x1000, },
	{ .name = "hwkm_prng_ee7", .flags = IOMMU_READ,
		.da = 0x10d7000, .pa = 0x10d7000, .len = 0x1000, },
	{ .name = "qos_usb_ufs_pcie", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x16c2000, .pa = 0x16c2000, .len = 0x9000, },
	{ .name = "qos_ufs_ipa_crypto", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1703000, .pa = 0x1703000, .len = 0x5000, },
	{ .name = "qos_misc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x178d000, .pa = 0x178d000, .len = 0x1000, },
	{ .name = "hw_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1f40000, .pa = 0x1f40000, .len = 0x40000, },
	{ .name = "tcsr_rw", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1fc0000, .pa = 0x1fc0000, .len = 0x9000, },
	{ .name = "tcsr_ro", .flags = IOMMU_READ,
		.da = 0x1fc9000, .pa = 0x1fc9000, .len = 0x22000, },
	{ .name = "tcsr_timeout_intr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1feb000, .pa = 0x1feb000, .len = 0x1000, },
	{ .name = "tcsr_ro2", .flags = IOMMU_READ,
		.da = 0x1fec000, .pa = 0x1fec000, .len = 0x4000, },
	{ .name = "tcsr_spare", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1ffb000, .pa = 0x1ffb000, .len = 0x1000, },
	{ .name = "lpass_lpm0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3140000, .pa = 0x3140000, .len = 0x29000, },
	{ .name = "lpass_lpm1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3180000, .pa = 0x3180000, .len = 0x29000, },
	{ .name = "lpass_lpm2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3260000, .pa = 0x3260000, .len = 0x10000, },
	{ .name = "lpass_lpm3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3280000, .pa = 0x3280000, .len = 0x29000, },
	{ .name = "lpass_lpm4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x32c0000, .pa = 0x32c0000, .len = 0x29000, },
	{ .name = "lpass_lpm5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x33c0000, .pa = 0x33c0000, .len = 0x29000, },
	{ .name = "lpass_lpm6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x33ec000, .pa = 0x33ec000, .len = 0x3000, },
	{ .name = "lpass_lpm7", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3a10000, .pa = 0x3a10000, .len = 0x8000, },
	{ .name = "lpass_lpm8", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3b00000, .pa = 0x3b00000, .len = 0x29000, },
	{ .name = "lpass_lpm9", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3b40000, .pa = 0x3b40000, .len = 0x29000, },
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
		.da = 0x4048000, .pa = 0x4048000, .len = 0x1000, },
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
	{ .name = "llcc_trp6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9a00000, .pa = 0x9a00000, .len = 0x28000, },
	{ .name = "pdc_seq_mem_a", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb240000, .pa = 0xb240000, .len = 0x10000, },
	{ .name = "pdc_seq_mem0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb2c0000, .pa = 0xb2c0000, .len = 0x10000, },
	{ .name = "pdc_rsc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb2f0000, .pa = 0xb2f0000, .len = 0x10000, },
	{ .name = "pdc_seq_mem1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb440000, .pa = 0xb440000, .len = 0x10000, },
	{ .name = "pdc_seq_mem2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb4c0000, .pa = 0xb4c0000, .len = 0x10000, },
	{ .name = "pdc_rsc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb4f0000, .pa = 0xb4f0000, .len = 0x10000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ,
		.da = 0xbbf0000, .pa = 0xbbf0000, .len = 0x2000, },
	{ .name = "mpm", .flags = IOMMU_READ,
		.da = 0xc210000, .pa = 0xc210000, .len = 0x80000, },
	{ .name = "rpmh_drv_gpdsp", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc330000, .pa = 0xc330000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc350000, .pa = 0xc350000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv1", .flags = IOMMU_READ,
		.da = 0xc370000, .pa = 0xc370000, .len = 0x1000, },
	{ .name = "rpmh_drv8_aop", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc380000, .pa = 0xc380000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv2", .flags = IOMMU_READ,
		.da = 0xc390000, .pa = 0xc390000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv3", .flags = IOMMU_READ,
		.da = 0xc3a0000, .pa = 0xc3a0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv4", .flags = IOMMU_READ,
		.da = 0xc3b0000, .pa = 0xc3b0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv5", .flags = IOMMU_READ,
		.da = 0xc3c0000, .pa = 0xc3c0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv6", .flags = IOMMU_READ,
		.da = 0xc3d0000, .pa = 0xc3d0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv7", .flags = IOMMU_READ,
		.da = 0xc3e0000, .pa = 0xc3e0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv8", .flags = IOMMU_READ,
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
	/* GP-DSP0 exclusive DDR (RW to GPDSP0 only) */
	{ .name = "gpdsp0_ddr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x20000000, .pa = 0x20000000, .len = 0x1000000, },
	{ .name = "emac0", .flags = IOMMU_READ,
		.da = 0x23000000, .pa = 0x23000000, .len = 0x30000, },
	{ .name = "emac1", .flags = IOMMU_READ,
		.da = 0x23040000, .pa = 0x23040000, .len = 0x30000, },
	{ .name = "nsp_7806", .flags = IOMMU_READ,
		.da = 0x90860000, .pa = 0x90860000, .len = 0x20000, },
	/* SMEM (smem@90900000, 2 MB) holds the GLINK FIFOs the DSP must
	 * read/write to talk to the apps processor. Without this mapping the
	 * DSP takes a translation fault on its first SMEM access (e.g. iova
	 * 0x90aff330) -> mmufault/watchdog and never reaches running.
	 */
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x90900000, .pa = 0x90900000, .len = 0x200000, },
};

DEFINE_RESOURCE_TABLE(GPDSP0, ARRAY_SIZE(turing_mem_res));

#define BOOT_FSM_TIMEOUT	10000

static TEE_Result gpdsp0_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timeout = timeout_init_us(BOOT_FSM_TIMEOUT);

	/* Program firmware entry; clocks/PLL are set up by the clock driver. */
	io_write32(base + GPDSP_QDSP6SS_RST_EVB, data->fw_base >> 4);
	dsb();

	/*
	 * De-assert stop-core, then trigger the boot FSM. The Q6 PLL and core
	 * RCG were already configured by gpdsp_setup() in the clock driver.
	 */
	io_setbits32(base + GPDSP_QDSP6SS_BOOT_CORE_START, BIT(0));
	udelay(5);
	io_write32(base + GPDSP_QDSP6SS_BOOT_CMD, 0x1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(base + GPDSP_QDSP6SS_BOOT_STATUS) & BIT(0))
			return TEE_SUCCESS;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result gpdsp0_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
}

static TEE_Result gpdsp0_get_resource_table(struct resource_table *rt,
					    size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = GPDSP0_NUM_MEM_RESOURCES,
		.offset[GPDSP0_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   turing_mem_res,
			   GPDSP0_RESOURCE_TABLE_HEADER_SIZE,
			   GPDSP0_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops gpdsp0_ops = {
	.fw_start = gpdsp0_fw_start,
	.fw_shutdown = gpdsp0_fw_shutdown,
	.get_resource_table = gpdsp0_get_resource_table,
};
