// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>
#include <util.h>

#include "lmcu.h"

/*
 * Registers below are offsets from MCU_MCU_CNOC_MASTER_BASE. TZ HWIO
 * defines MCU_RVCP_CSR_REG_BASE as MCU_MCU_CNOC_MASTER_BASE + 0x40000;
 * these offsets include that CSR-base delta.
 */
#define MCU_RVCP_TILE0_RESET_VECTOR		0x8c018

/*
 * Each remapper maps a fixed 64MB LMCU-side address range, starting at
 * 0x40000000, to a configurable ANOC-side (SOC) address. The value to
 * program is the ANOC-side address ORed with 0x1 to enable the remapper.
 */
#define MCU_RVCP_NONCACHE_SID_REMAPPER_0	0x8d000
#define MCU_RVCP_NONCACHE_SID_REMAPPER_1	0x8d008
#define MCU_RVCP_NONCACHE_SID_REMAPPER_2	0x8d010
#define MCU_RVCP_NONCACHE_SID_REMAPPER_3	0x8d018
#define MCU_RVCP_NONCACHE_SID_REMAPPER_4	0x8d020
#define MCU_RVCP_NONCACHE_SID_REMAPPER_5	0x8d028
#define MCU_RVCP_NONCACHE_SID_REMAPPER_6	0x8d030
#define MCU_RVCP_NONCACHE_SID_REMAPPER_7	0x8d038
#define MCU_RVCP_NONCACHE_SID_REMAPPER_8	0x8d040
#define MCU_RVCP_NONCACHE_SID_REMAPPER_9	0x8d048
#define MCU_RVCP_NONCACHE_SID_REMAPPER_10	0x8d050
#define MCU_RVCP_NONCACHE_SID_REMAPPER_11	0x8d058
#define MCU_RVCP_NONCACHE_SID_REMAPPER_12	0x8d060
#define MCU_RVCP_NONCACHE_SID_REMAPPER_13	0x8d068
#define MCU_RVCP_NONCACHE_SID_REMAPPER_14	0x8d070
#define MCU_RVCP_NONCACHE_SID_REMAPPER_15	0x8d078

/*
 * SID registers select which stream ID LMCU uses for bus transactions
 * against a given remapped range. Values come from the target's SMMU
 * configuration.
 */
#define MCU_RVCP_NONCACHE_SID0			0x8d200
#define MCU_RVCP_NONCACHE_SID1			0x8d204
#define MCU_RVCP_NONCACHE_SID2			0x8d208
#define MCU_RVCP_NONCACHE_SID3			0x8d20c
#define MCU_RVCP_NONCACHE_SID4			0x8d210
#define MCU_RVCP_NONCACHE_SID5			0x8d214
#define MCU_RVCP_NONCACHE_SID6			0x8d218
#define MCU_RVCP_NONCACHE_SID7			0x8d21c
#define MCU_RVCP_NONCACHE_SID8			0x8d220
#define MCU_RVCP_NONCACHE_SID9			0x8d224
#define MCU_RVCP_NONCACHE_SID10			0x8d228
#define MCU_RVCP_NONCACHE_SID11			0x8d22c
#define MCU_RVCP_NONCACHE_SID12			0x8d230
#define MCU_RVCP_NONCACHE_SID13			0x8d234
#define MCU_RVCP_NONCACHE_SID14			0x8d238
#define MCU_RVCP_NONCACHE_SID15			0x8d23c
#define MCU_RVCP_NONCACHE_SID17			0x8d244
#define MCU_RVCP_CACHE_SID0			0x8d300

#define MCU_RVCP_SID_BMSK			0xf
#define MCU_RVCP_SID_SHFT			0

static const struct fw_rsc_devmem lmcu_mem_res[] = {
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00340000, .pa = 0x00340000, .len = 0x00008000, },
	{ .name = "tcsr_wonce", .flags = IOMMU_READ,
		.da = 0x003d4000, .pa = 0x003d4000, .len = 0x00001000, },
	{ .name = "tcsr_intr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x003e1000, .pa = 0x003e1000, .len = 0x00001000, },
	{ .name = "tlmm_reg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x00500000, .pa = 0x00500000, .len = 0x00700000, },
	{ .name = "gcc_clk_ctl_0", .flags = IOMMU_READ,
		.da = 0x01400000, .pa = 0x01400000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_1", .flags = IOMMU_READ,
		.da = 0x01406000, .pa = 0x01406000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01410000, .pa = 0x01410000, .len = 0x00002000, },
	{ .name = "gcc_clk_ctl_3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0141f000, .pa = 0x0141f000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01423000, .pa = 0x01423000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01428000, .pa = 0x01428000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01475000, .pa = 0x01475000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_rg170", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x014aa000, .pa = 0x014aa000, .len = 0x00001000, },
	{ .name = "gcc_clk_ctl_rg179", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x014b3000, .pa = 0x014b3000, .len = 0x00001000, },
	{ .name = "system_noc", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x018e8000, .pa = 0x018e8000, .len = 0x00001000, },
	{ .name = "spmi_cfg_top", .flags = IOMMU_READ,
		.da = 0x01c00000, .pa = 0x01c00000, .len = 0x00030000, },
	{ .name = "pmic_arb_core", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x01c40000, .pa = 0x01c40000, .len = 0x00010000, },
	{ .name = "pmic_arb_mgpi", .flags = IOMMU_READ,
		.da = 0x01c60000, .pa = 0x01c60000, .len = 0x00081000, },
	{ .name = "pmic_arb_obs", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x03e00000, .pa = 0x03e00000, .len = 0x00100000, },
	{ .name = "spmi_pic_owner", .flags = IOMMU_READ,
		.da = 0x03f00000, .pa = 0x03f00000, .len = 0x000a0000, },
	{ .name = "rpm_msg_ram_rw", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x045f2000, .pa = 0x045f2000, .len = 0x00001000, },
	{ .name = "rpm_msg_ram_ro", .flags = IOMMU_READ,
		.da = 0x045f6000, .pa = 0x045f6000, .len = 0x00001000, },
	{ .name = "qdss_mcu_debug", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x08980000, .pa = 0x08980000, .len = 0x00010000, },
	{ .name = "mcu_dls", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x0b940000, .pa = 0x0b940000, .len = 0x000c0000, },
	{ .name = "qdss_stm", .flags = IOMMU_WRITE,
		.da = 0x0e000000, .pa = 0x0e000000, .len = 0x01000000, },
	{ .name = "qup_3_0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x04a00000, .pa = 0x04a00000, .len = 0x00100000, },
	/*
	 * DSP takes a translation fault on its first SMEM access.
	 * Without this mapping it hits an mmu fault/watchdog and
	 * never reaches the running state.
	 */
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x86000000, .pa = 0x86000000, .len = 0x200000, },
};

DEFINE_RESOURCE_TABLE(LMCU, ARRAY_SIZE(lmcu_mem_res));

static void lmcu_write_sid(vaddr_t base, uint32_t reg, uint32_t sid)
{
	io_mask32(base + reg, SHIFT_U32(sid, MCU_RVCP_SID_SHFT),
		  MCU_RVCP_SID_BMSK);
}

static TEE_Result lmcu_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	static const struct {
		uint32_t reg;
		uint32_t val;
	} remappers[] = {
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_0,  0x00000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_1,  0x04000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_2,  0x08000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_3,  0x0c000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_4,  0x10000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_5,  0x14000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_6,  0x18000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_7,  0x1c000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_8,  0x20000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_9,  0x24000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_10, 0x28000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_11, 0x2c000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_12, 0x30000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_13, 0x34000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_14, 0x38000001 },
		{ MCU_RVCP_NONCACHE_SID_REMAPPER_15, 0x3c000001 },
	};
	static const uint32_t noncache_sids[] = {
		MCU_RVCP_NONCACHE_SID0,  MCU_RVCP_NONCACHE_SID1,
		MCU_RVCP_NONCACHE_SID2,  MCU_RVCP_NONCACHE_SID3,
		MCU_RVCP_NONCACHE_SID4,  MCU_RVCP_NONCACHE_SID5,
		MCU_RVCP_NONCACHE_SID6,  MCU_RVCP_NONCACHE_SID7,
		MCU_RVCP_NONCACHE_SID8,  MCU_RVCP_NONCACHE_SID9,
		MCU_RVCP_NONCACHE_SID10, MCU_RVCP_NONCACHE_SID11,
		MCU_RVCP_NONCACHE_SID12, MCU_RVCP_NONCACHE_SID13,
		MCU_RVCP_NONCACHE_SID14, MCU_RVCP_NONCACHE_SID15,
	};

	if (!base)
		return TEE_ERROR_GENERIC;

	for (size_t i = 0; i < ARRAY_SIZE(remappers); i++)
		io_write32(base + remappers[i].reg, remappers[i].val);

	for (size_t i = 0; i < ARRAY_SIZE(noncache_sids); i++)
		lmcu_write_sid(base, noncache_sids[i], 4);

	lmcu_write_sid(base, MCU_RVCP_NONCACHE_SID17, 0);
	lmcu_write_sid(base, MCU_RVCP_CACHE_SID0, 0);

	/*
	 * Program the firmware entry point. Unlike the Q6-based subsystems,
	 * LMCU's reset vector is a plain address, not shifted. The core
	 * itself is released later, once its clock is configured, by
	 * qcom_clock_enable_pas_processor().
	 */
	io_write32(base + MCU_RVCP_TILE0_RESET_VECTOR, (uint32_t)data->fw_base);
	dsb();

	return TEE_SUCCESS;
}

static TEE_Result lmcu_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
}

static TEE_Result lmcu_dtb_fw_start(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result lmcu_dtb_fw_shutdown(struct qcom_pas_data *data __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result lmcu_get_resource_table(struct resource_table *rt,
					  size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = LMCU_NUM_MEM_RESOURCES,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   lmcu_mem_res,
			   LMCU_RESOURCE_TABLE_HEADER_SIZE,
			   LMCU_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops lmcu_ops = {
	.fw_start = lmcu_fw_start,
	.fw_shutdown = lmcu_fw_shutdown,
	.get_resource_table = lmcu_get_resource_table,
};

const struct qcom_pas_ops lmcu_dtb_ops = {
	.fw_start = lmcu_dtb_fw_start,
	.fw_shutdown = lmcu_dtb_fw_shutdown,
};
