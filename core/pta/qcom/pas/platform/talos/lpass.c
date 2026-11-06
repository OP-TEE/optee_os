// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_qdsp6ss.h>
#include <io.h>
#include <kernel/delay.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

#include "lpass.h"

/* Relative to LPASS_BASE */
#define LPASS_QDSP6SS			0x400000
#define SCC_SSC_EFUSE_Q6SS_EVB_SEL	0xb0b000
#define SCC_SSC_EFUSE_Q6SS_EVB_ADDR	0xb0b004

#define BOOT_FSM_TIMEOUT_US		1000000

/*
 * Peripherals the ADSP reaches through its SMMU stream, identity mapped,
 * plus the command DB and SMEM.
 */
static const struct fw_rsc_devmem lpass_mem_res[] = {
	{ .name = "gcc", .flags = IOMMU_READ,
		.da = 0x00100000, .pa = 0x00100000, .len = 0x0000e000, },
	{ .name = "gcc1", .flags = IOMMU_READ,
		.da = 0x0010f000, .pa = 0x0010f000, .len = 0x00008000, },
	{ .name = "gcc2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00117000, .pa = 0x00117000, .len = 0x00002000, },
	{ .name = "gcc3", .flags = IOMMU_READ,
		.da = 0x00119000, .pa = 0x00119000, .len = 0x0002a000, },
	{ .name = "gcc4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00143000, .pa = 0x00143000, .len = 0x00001000, },
	{ .name = "gcc5", .flags = IOMMU_READ,
		.da = 0x00144000, .pa = 0x00144000, .len = 0x00002000, },
	{ .name = "gcc6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00146000, .pa = 0x00146000, .len = 0x00002000, },
	{ .name = "gcc7", .flags = IOMMU_READ,
		.da = 0x00148000, .pa = 0x00148000, .len = 0x0000c000, },
	{ .name = "gcc8", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00154000, .pa = 0x00154000, .len = 0x00002000, },
	{ .name = "gcc9", .flags = IOMMU_READ,
		.da = 0x00156000, .pa = 0x00156000, .len = 0x0000c000, },
	{ .name = "gcc10", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00162000, .pa = 0x00162000, .len = 0x00001000, },
	{ .name = "gcc11", .flags = IOMMU_READ,
		.da = 0x00163000, .pa = 0x00163000, .len = 0x0018d000, },
	{ .name = "security_ctrl", .flags = IOMMU_READ,
		.da = 0x00780000, .pa = 0x00780000, .len = 0x00007000, },
	{ .name = "prng", .flags = IOMMU_READ,
		.da = 0x00790000, .pa = 0x00790000, .len = 0x00001000, },
	{ .name = "prng1", .flags = IOMMU_READ,
		.da = 0x00795000, .pa = 0x00795000, .len = 0x00001000, },
	{ .name = "prng2", .flags = IOMMU_READ,
		.da = 0x0079a000, .pa = 0x0079a000, .len = 0x00001000, },
	{ .name = "aggre_noc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01707000, .pa = 0x01707000, .len = 0x00002000, },
	{ .name = "aggre_noc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01714000, .pa = 0x01714000, .len = 0x00001000, },
	{ .name = "crypto", .flags = IOMMU_READ,
		.da = 0x01dc4000, .pa = 0x01dc4000, .len = 0x00001000, },
	{ .name = "crypto1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01dc5000, .pa = 0x01dc5000, .len = 0x00001000, },
	{ .name = "crypto2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01dc8000, .pa = 0x01dc8000, .len = 0x00001000, },
	{ .name = "crypto3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01dfa000, .pa = 0x01dfa000, .len = 0x00001000, },
	{ .name = "crypto4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01dfd000, .pa = 0x01dfd000, .len = 0x00001000, },
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01f40000, .pa = 0x01f40000, .len = 0x00040000, },
	{ .name = "tcsr", .flags = IOMMU_READ,
		.da = 0x01fc0000, .pa = 0x01fc0000, .len = 0x0000b000, },
	{ .name = "tcsr1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01fcb000, .pa = 0x01fcb000, .len = 0x00001000, },
	{ .name = "tcsr2", .flags = IOMMU_READ,
		.da = 0x01fcc000, .pa = 0x01fcc000, .len = 0x0001d000, },
	{ .name = "tcsr3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01fe9000, .pa = 0x01fe9000, .len = 0x00001000, },
	{ .name = "tcsr4", .flags = IOMMU_READ,
		.da = 0x01fea000, .pa = 0x01fea000, .len = 0x00006000, },
	{ .name = "tlmm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x03000000, .pa = 0x03000000, .len = 0x01000000, },
	{ .name = "qdss", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06001000, .pa = 0x06001000, .len = 0x00002000, },
	{ .name = "qdss1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06041000, .pa = 0x06041000, .len = 0x00002000, },
	{ .name = "qdss2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06045000, .pa = 0x06045000, .len = 0x00004000, },
	{ .name = "qdss_swao", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06b08000, .pa = 0x06b08000, .len = 0x00002000, },
	{ .name = "qdss_swao1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06b0e000, .pa = 0x06b0e000, .len = 0x00001000, },
	{ .name = "qdss_ssc_dbg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06b10000, .pa = 0x06b10000, .len = 0x0000f000, },
	{ .name = "ddr_reg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x090c0000, .pa = 0x090c0000, .len = 0x00001000, },
	{ .name = "llcc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09200000, .pa = 0x09200000, .len = 0x00028000, },
	{ .name = "llcc_bcast", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09600000, .pa = 0x09600000, .len = 0x00028000, },
	{ .name = "usb3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0a600000, .pa = 0x0a600000, .len = 0x0000d000, },
	{ .name = "mdss", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0ae00000, .pa = 0x0ae00000, .len = 0x000c0000, },
	{ .name = "pdc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b230000, .pa = 0x0b230000, .len = 0x00010000, },
	{ .name = "pdc_seq", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b430000, .pa = 0x0b430000, .len = 0x00010000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ,
		.da = 0x0bbf0000, .pa = 0x0bbf0000, .len = 0x00002000, },
	{ .name = "aoss_mpm", .flags = IOMMU_READ,
		.da = 0x0c210000, .pa = 0x0c210000, .len = 0x00080000, },
	{ .name = "aop_msg_ram", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c340000, .pa = 0x0c340000, .len = 0x00001000, },
	{ .name = "aop_msg_ram1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c350000, .pa = 0x0c350000, .len = 0x00001000, },
	{ .name = "aop_msg_ram2", .flags = IOMMU_READ,
		.da = 0x0c370000, .pa = 0x0c370000, .len = 0x00001000, },
	{ .name = "aop_msg_ram3", .flags = IOMMU_READ,
		.da = 0x0c380000, .pa = 0x0c380000, .len = 0x00001000, },
	{ .name = "aop_msg_ram4", .flags = IOMMU_READ,
		.da = 0x0c390000, .pa = 0x0c390000, .len = 0x00001000, },
	{ .name = "aop_msg_ram5", .flags = IOMMU_READ,
		.da = 0x0c3a0000, .pa = 0x0c3a0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram6", .flags = IOMMU_READ,
		.da = 0x0c3b0000, .pa = 0x0c3b0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram7", .flags = IOMMU_READ,
		.da = 0x0c3c0000, .pa = 0x0c3c0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram8", .flags = IOMMU_READ,
		.da = 0x0c3d0000, .pa = 0x0c3d0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram9", .flags = IOMMU_READ,
		.da = 0x0c3e0000, .pa = 0x0c3e0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram10", .flags = IOMMU_READ,
		.da = 0x0c3f0000, .pa = 0x0c3f0000, .len = 0x00001000, },
	{ .name = "spmi", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c400000, .pa = 0x0c400000, .len = 0x00030000, },
	{ .name = "pmic_arb", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c440000, .pa = 0x0c440000, .len = 0x00010000, },
	{ .name = "pmic_arb_mgpi", .flags = IOMMU_READ,
		.da = 0x0c460000, .pa = 0x0c460000, .len = 0x00051000, },
	{ .name = "pmic_arb_obs", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0e600000, .pa = 0x0e600000, .len = 0x00100000, },
	{ .name = "spmi_pic", .flags = IOMMU_READ,
		.da = 0x0e700000, .pa = 0x0e700000, .len = 0x000a0000, },
	{ .name = "system_imem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x146a6000, .pa = 0x146a6000, .len = 0x00005000, },
	{ .name = "qdss_stm", .flags = IOMMU_WRITE,
		.da = 0x16000000, .pa = 0x16000000, .len = 0x01000000, },
	{ .name = "cmd_db", .flags = IOMMU_READ,
		.da = 0x85f20000, .pa = 0x85f20000, .len = 0x00020000, },
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x86000000, .pa = 0x86000000, .len = 0x00200000, },
};

static TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint32_t evb = QDSP6SS_EVB_ADDR(data->fw_base);

	if (!base)
		return TEE_ERROR_GENERIC;

	/* The ADSP boots from the address in the EFUSE EVB register */
	io_setbits32(base + SCC_SSC_EFUSE_Q6SS_EVB_SEL, BIT(0));
	io_write32(base + SCC_SSC_EFUSE_Q6SS_EVB_ADDR, evb);
	dsb();

	if ((io_read32(base + SCC_SSC_EFUSE_Q6SS_EVB_ADDR) &
	     QDSP6SS_EVB_ADDR_MASK) != evb) {
		EMSG("ADSP boot address not taken");
		return TEE_ERROR_GENERIC;
	}

	qcom_qdsp6ss_core_start(base + LPASS_QDSP6SS);
	udelay(5);
	return qcom_qdsp6ss_boot_fsm(base + LPASS_QDSP6SS, BOOT_FSM_TIMEOUT_US);
}

const struct qcom_pas_ops lpass_ops = {
	.fw_start = lpass_fw_start,
	.devmem = lpass_mem_res,
	.devmem_num = ARRAY_SIZE(lpass_mem_res),
};
