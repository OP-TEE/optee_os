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

#include "cdsp.h"

/* Relative to TURING_BASE */
#define TURING_QDSP6SS			0x300000

#define BOOT_FSM_TIMEOUT_US		1000000

/*
 * Peripherals the CDSP reaches through its SMMU stream, identity mapped,
 * plus the command DB and SMEM.
 */
static const struct fw_rsc_devmem turing_mem_res[] = {
	{ .name = "gcc", .flags = IOMMU_READ,
		.da = 0x00100000, .pa = 0x00100000, .len = 0x00004000, },
	{ .name = "gcc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00104000, .pa = 0x00104000, .len = 0x00001000, },
	{ .name = "gcc2", .flags = IOMMU_READ,
		.da = 0x00105000, .pa = 0x00105000, .len = 0x00009000, },
	{ .name = "gcc3", .flags = IOMMU_READ,
		.da = 0x0010f000, .pa = 0x0010f000, .len = 0x00008000, },
	{ .name = "gcc4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00117000, .pa = 0x00117000, .len = 0x00002000, },
	{ .name = "gcc5", .flags = IOMMU_READ,
		.da = 0x00119000, .pa = 0x00119000, .len = 0x0002a000, },
	{ .name = "gcc6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00143000, .pa = 0x00143000, .len = 0x00001000, },
	{ .name = "gcc7", .flags = IOMMU_READ,
		.da = 0x00144000, .pa = 0x00144000, .len = 0x00001000, },
	{ .name = "gcc8", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00145000, .pa = 0x00145000, .len = 0x00001000, },
	{ .name = "gcc9", .flags = IOMMU_READ,
		.da = 0x00146000, .pa = 0x00146000, .len = 0x00015000, },
	{ .name = "gcc10", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0015b000, .pa = 0x0015b000, .len = 0x00001000, },
	{ .name = "gcc11", .flags = IOMMU_READ,
		.da = 0x0015c000, .pa = 0x0015c000, .len = 0x00006000, },
	{ .name = "gcc12", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00162000, .pa = 0x00162000, .len = 0x00001000, },
	{ .name = "gcc13", .flags = IOMMU_READ,
		.da = 0x00163000, .pa = 0x00163000, .len = 0x00028000, },
	{ .name = "gcc14", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0018b000, .pa = 0x0018b000, .len = 0x00001000, },
	{ .name = "gcc15", .flags = IOMMU_READ,
		.da = 0x0018c000, .pa = 0x0018c000, .len = 0x00164000, },
	{ .name = "security_ctrl", .flags = IOMMU_READ,
		.da = 0x00780000, .pa = 0x00780000, .len = 0x00010000, },
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01f40000, .pa = 0x01f40000, .len = 0x00040000, },
	{ .name = "tcsr", .flags = IOMMU_READ,
		.da = 0x01fc0000, .pa = 0x01fc0000, .len = 0x0002b000, },
	{ .name = "tcsr1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01feb000, .pa = 0x01feb000, .len = 0x00001000, },
	{ .name = "tcsr2", .flags = IOMMU_READ,
		.da = 0x01fec000, .pa = 0x01fec000, .len = 0x00001000, },
	{ .name = "tcsr3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01fed000, .pa = 0x01fed000, .len = 0x00001000, },
	{ .name = "tcsr4", .flags = IOMMU_READ,
		.da = 0x01fee000, .pa = 0x01fee000, .len = 0x00002000, },
	{ .name = "tlmm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x03000000, .pa = 0x03000000, .len = 0x00c00000, },
	{ .name = "qdss", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06001000, .pa = 0x06001000, .len = 0x00002000, },
	{ .name = "qdss1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06041000, .pa = 0x06041000, .len = 0x00002000, },
	{ .name = "qdss2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x06045000, .pa = 0x06045000, .len = 0x00004000, },
	{ .name = "cdsp_bwmon", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x090b8000, .pa = 0x090b8000, .len = 0x00001000, },
	{ .name = "ddr_reg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x090c0000, .pa = 0x090c0000, .len = 0x00001000, },
	{ .name = "llcc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09200000, .pa = 0x09200000, .len = 0x00028000, },
	{ .name = "llcc_bcast", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x09600000, .pa = 0x09600000, .len = 0x00028000, },
	{ .name = "gemnoc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x096ad000, .pa = 0x096ad000, .len = 0x00001000, },
	{ .name = "pdc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b280000, .pa = 0x0b280000, .len = 0x00010000, },
	{ .name = "pdc_seq", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b480000, .pa = 0x0b480000, .len = 0x00010000, },
	{ .name = "rpmh_bcm", .flags = IOMMU_READ,
		.da = 0x0bbf0000, .pa = 0x0bbf0000, .len = 0x00002000, },
	{ .name = "aoss_mpm", .flags = IOMMU_READ,
		.da = 0x0c210000, .pa = 0x0c210000, .len = 0x00080000, },
	{ .name = "aop_msg_ram", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0c330000, .pa = 0x0c330000, .len = 0x00001000, },
	{ .name = "aop_msg_ram1", .flags = IOMMU_READ,
		.da = 0x0c370000, .pa = 0x0c370000, .len = 0x00001000, },
	{ .name = "aop_msg_ram2", .flags = IOMMU_READ,
		.da = 0x0c380000, .pa = 0x0c380000, .len = 0x00001000, },
	{ .name = "aop_msg_ram3", .flags = IOMMU_READ,
		.da = 0x0c390000, .pa = 0x0c390000, .len = 0x00001000, },
	{ .name = "aop_msg_ram4", .flags = IOMMU_READ,
		.da = 0x0c3a0000, .pa = 0x0c3a0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram5", .flags = IOMMU_READ,
		.da = 0x0c3b0000, .pa = 0x0c3b0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram6", .flags = IOMMU_READ,
		.da = 0x0c3c0000, .pa = 0x0c3c0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram7", .flags = IOMMU_READ,
		.da = 0x0c3d0000, .pa = 0x0c3d0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram8", .flags = IOMMU_READ,
		.da = 0x0c3e0000, .pa = 0x0c3e0000, .len = 0x00001000, },
	{ .name = "aop_msg_ram9", .flags = IOMMU_READ,
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
		.da = 0x146aa000, .pa = 0x146aa000, .len = 0x00001000, },
	{ .name = "qdss_stm", .flags = IOMMU_WRITE,
		.da = 0x16000000, .pa = 0x16000000, .len = 0x01000000, },
	{ .name = "cmd_db", .flags = IOMMU_READ,
		.da = 0x85f20000, .pa = 0x85f20000, .len = 0x00020000, },
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x86000000, .pa = 0x86000000, .len = 0x00200000, },
};

static TEE_Result cdsp_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);

	if (!base)
		return TEE_ERROR_GENERIC;

	io_write32(base + TURING_QDSP6SS + QDSP6SS_RST_EVB,
		   QDSP6SS_EVB_ADDR(data->fw_base));
	dsb();

	qcom_qdsp6ss_core_start(base + TURING_QDSP6SS);
	udelay(5);
	return qcom_qdsp6ss_boot_fsm(base + TURING_QDSP6SS,
				     BOOT_FSM_TIMEOUT_US);
}

const struct qcom_pas_ops cdsp_ops = {
	.fw_start = cdsp_fw_start,
	.devmem = turing_mem_res,
	.devmem_num = ARRAY_SIZE(turing_mem_res),
};
