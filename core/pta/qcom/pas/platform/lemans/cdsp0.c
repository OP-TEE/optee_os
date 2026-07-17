// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

#include "cdsp0.h"

#define TURING_NSPAUX_XO_CBCR		0x02008040
#define TURING_Q6SS_Q6_AXIM_CBCR	0x02008404
#define TURING_Q6SS_AXIS2_CBCR		0x0200840c

#define TURING_QDSP6SS_CORE_CBCR	0x02348040

#define TURING_QDSP6SS_RST_EVB		0x02300010
#define TURING_QDSP6SS_BOOT_CMD		0x02300404
#define TURING_QDSP6SS_BOOT_STATUS	0x02300408

static const struct fw_rsc_devmem turing_mem_res[] = {
	{ .name = "gcc_gpll0_3", .flags = IOMMU_READ,
		.da = 0x110000, .pa = 0x110000, .len = 0x4000, },
	{ .name = "gcc_turing1_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x114000, .pa = 0x114000, .len = 0xf000, },
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
	{ .name = "gcc_turing0_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x149000, .pa = 0x149000, .len = 0xc000, },
	{ .name = "gcc_turing0_gdscr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x155000, .pa = 0x155000, .len = 0x1000, },
	{ .name = "gcc_turing_dsp_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x16b000, .pa = 0x16b000, .len = 0x1000, },
	{ .name = "gcc_clk_frq_measure", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x172000, .pa = 0x172000, .len = 0x1000, },
	{ .name = "gcc_turing0_pll_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x173000, .pa = 0x173000, .len = 0x11000, },
	{ .name = "gcc_gpll5", .flags = IOMMU_READ,
		.da = 0x184000, .pa = 0x184000, .len = 0x1000, },
	{ .name = "gcc_gpll4", .flags = IOMMU_READ,
		.da = 0x186000, .pa = 0x186000, .len = 0x1000, },
	{ .name = "gcc_turing1_pll_vote", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x187000, .pa = 0x187000, .len = 0x45000, },
	{ .name = "gcc_turing1_gdscr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1cc000, .pa = 0x1cc000, .len = 0x1000, },
	{ .name = "mproc_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x406000, .pa = 0x406000, .len = 0x1000, },
	{ .name = "mproc_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x412000, .pa = 0x412000, .len = 0x1000, },
	{ .name = "computel0_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x446000, .pa = 0x446000, .len = 0x1000, },
	{ .name = "computel0_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x452000, .pa = 0x452000, .len = 0x1000, },
	{ .name = "computel1_ipc_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x486000, .pa = 0x486000, .len = 0x1000, },
	{ .name = "computel1_ipc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x492000, .pa = 0x492000, .len = 0x1000, },
	{ .name = "periph_ipc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4c6000, .pa = 0x4c6000, .len = 0x1000, },
	{ .name = "periph_ipc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4d2000, .pa = 0x4d2000, .len = 0x1000, },
	{ .name = "ipc_mode", .flags = IOMMU_READ,
		.da = 0x4fc000, .pa = 0x4fc000, .len = 0x1000, },
	{ .name = "nspcx0_cpr3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x63a000, .pa = 0x63a000, .len = 0x4000, },
	{ .name = "nsp_cprf_cprc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x63e000, .pa = 0x63e000, .len = 0x4000, },
	{ .name = "oem_fuses", .flags = IOMMU_READ,
		.da = 0x780000, .pa = 0x780000, .len = 0x10000, },
	{ .name = "hwkm_prng_cm", .flags = IOMMU_READ,
		.da = 0x10d0000, .pa = 0x10d0000, .len = 0x1000, },
	{ .name = "hwkm_prng_ee10", .flags = IOMMU_READ,
		.da = 0x10da000, .pa = 0x10da000, .len = 0x1000, },
	{ .name = "qos_usb_ufs_pcie", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x16c2000, .pa = 0x16c2000, .len = 0x9000, },
	{ .name = "qos_ufs_ipa_crypto", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1703000, .pa = 0x1703000, .len = 0x5000, },
	{ .name = "hw_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1f40000, .pa = 0x1f40000, .len = 0x40000, },
	{ .name = "tcsr_ro", .flags = IOMMU_READ,
		.da = 0x1fc0000, .pa = 0x1fc0000, .len = 0x2b000, },
	{ .name = "tcsr_timeout_intr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1feb000, .pa = 0x1feb000, .len = 0x1000, },
	{ .name = "tcsr_ro2", .flags = IOMMU_READ,
		.da = 0x1fec000, .pa = 0x1fec000, .len = 0x4000, },
	{ .name = "tcsr_spare_rg63", .flags = IOMMU_READ,
		.da = 0x1fff000, .pa = 0x1fff000, .len = 0x1000, },
	{ .name = "ddr_llc_info", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x9080000, .pa = 0x9080000, .len = 0x1000, },
	{ .name = "bwmon0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x90b4000, .pa = 0x90b4000, .len = 0x1000, },
	{ .name = "bwmon1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x90b8000, .pa = 0x90b8000, .len = 0x1000, },
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
	{ .name = "pdc_seq_mem0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb2c0000, .pa = 0xb2c0000, .len = 0x10000, },
	{ .name = "pdc_rsc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb2f0000, .pa = 0xb2f0000, .len = 0x10000, },
	{ .name = "pdc_seq_mem1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb4c0000, .pa = 0xb4c0000, .len = 0x10000, },
	{ .name = "pdc_rsc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xb4f0000, .pa = 0xb4f0000, .len = 0x10000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ,
		.da = 0xbbf0000, .pa = 0xbbf0000, .len = 0x2000, },
	{ .name = "rpmh_cprf_nsp9", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc20a000, .pa = 0xc20a000, .len = 0x1000, },
	{ .name = "rpmh_cprf_nsp10", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc20b000, .pa = 0xc20b000, .len = 0x1000, },
	{ .name = "mpm", .flags = IOMMU_READ,
		.da = 0xc210000, .pa = 0xc210000, .len = 0x80000, },
	{ .name = "rpmh_drv_cdsp", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0xc330000, .pa = 0xc330000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv0", .flags = IOMMU_READ,
		.da = 0xc370000, .pa = 0xc370000, .len = 0x1000, },
	{ .name = "rpmh_drv8_aop", .flags = IOMMU_READ | IOMMU_WRITE,
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
	{ .name = "rpmh_drv_rsv6", .flags = IOMMU_READ,
		.da = 0xc3e0000, .pa = 0xc3e0000, .len = 0x1000, },
	{ .name = "rpmh_drv_rsv7", .flags = IOMMU_READ,
		.da = 0xc3f0000, .pa = 0xc3f0000, .len = 0x1000, },
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
	{ .name = "emac1_ptp", .flags = IOMMU_READ,
		.da = 0x23007000, .pa = 0x23007000, .len = 0x1000, },
	{ .name = "emac0_ptp", .flags = IOMMU_READ,
		.da = 0x23047000, .pa = 0x23047000, .len = 0x1000, },
	{ .name = "emac_sgmii", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x2304e000, .pa = 0x2304e000, .len = 0x2000, },
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

DEFINE_RESOURCE_TABLE(TURING, ARRAY_SIZE(turing_mem_res));

#define BOOT_FSM_TIMEOUT	10000

/*
 * Clear the CDSP content-protection shared channel before starting the DSP.
 * TZ does this on CDSP0 bring-up only (ACResetSharedChannel, AC_VM_CP_CDSP);
 * there is no equivalent CDSP1 channel. Leaving stale contents here prevents
 * the host from communicating with CDSP0 even though the core boots.
 */
static TEE_Result cdsp0_reset_shared_channel(void)
{
	void *va = core_mmu_add_mapping(MEM_AREA_RAM_SEC,
					CDSP_SECCHANNEL_BASE,
					CDSP_SECCHANNEL_SIZE);

	if (!va) {
		EMSG("Failed to map CDSP shared channel");
		return TEE_ERROR_GENERIC;
	}

	memset(va, 0, CDSP_SECCHANNEL_SIZE);

	/*
	 * The channel is mapped write-back cacheable, so flush the zeros out
	 * to DDR before unmapping. The reference (ACResetSharedChannel) maps
	 * it write-through; without this clean the cleared contents can sit in
	 * the cache and the DSP/fastrpc reads stale data, so the link never
	 * comes up even though the core boots.
	 */
	dcache_clean_range(va, CDSP_SECCHANNEL_SIZE);

	if (core_mmu_remove_mapping(MEM_AREA_RAM_SEC, va,
				    CDSP_SECCHANNEL_SIZE)) {
		EMSG("Failed to unmap CDSP shared channel");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result cdsp0_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timeout = timeout_init_us(BOOT_FSM_TIMEOUT);
	TEE_Result res = TEE_SUCCESS;

	res = cdsp0_reset_shared_channel();
	if (res != TEE_SUCCESS)
		return res;

	/* QDSPV73SS out of reset sequence */
	io_setbits32(base + TURING_QDSP6SS_CORE_CBCR, CBCR_BRANCH_ENABLE_BIT);
	io_setbits32(base + TURING_Q6SS_Q6_AXIM_CBCR, CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(base + TURING_Q6SS_AXIS2_CBCR, CBCR_HW_CTL_ENABLE_BIT);
	io_setbits32(base + TURING_NSPAUX_XO_CBCR, CBCR_BRANCH_ENABLE_BIT);

	/* Program firmware */
	io_write32(base + TURING_QDSP6SS_RST_EVB, data->fw_base >> 4);
	dsb();

	/* Trigger the boot FSM. The core itself is released later, after the
	 * Q6 PLL is configured, by qcom_clock_enable_pas_processor().
	 */
	io_write32(base + TURING_QDSP6SS_BOOT_CMD, 0x1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(base + TURING_QDSP6SS_BOOT_STATUS) & BIT(0))
			return TEE_SUCCESS;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result cdsp0_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
}

static TEE_Result cdsp0_get_resource_table(struct resource_table *rt,
					   size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = TURING_NUM_MEM_RESOURCES,
		.offset[TURING_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   turing_mem_res,
			   TURING_RESOURCE_TABLE_HEADER_SIZE,
			   TURING_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops cdsp0_ops = {
	.fw_start = cdsp0_fw_start,
	.fw_shutdown = cdsp0_fw_shutdown,
	.get_resource_table = cdsp0_get_resource_table,
};
