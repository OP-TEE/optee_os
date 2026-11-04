// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/delay.h>
#include <platform_config.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "lpass.h"

/* Relative to LPASS_BASE */
#define LPASS_QDSP6SS_BOOT_CORE_START	0x400400
#define LPASS_QDSP6SS_BOOT_CMD		0x400404
#define LPASS_QDSP6SS_BOOT_STATUS	0x400408
#define LPASS_EFUSE_Q6SS_EVB_SEL	0x95b000
#define LPASS_EFUSE_Q6SS_EVB_ADDR	0x95b004

#define EVB_ADDR_MASK			GENMASK_32(27, 4)

#define BOOT_FSM_TIMEOUT_US		1000000

/*
 * Peripherals the ADSP reaches through its SMMU stream, identity mapped:
 * the Agatti "ADSP Q6 ELF" stage-2 aperture, plus SMEM.
 *
 * The aperture also lists PIMEM, the modem (MSS_TOP), WLAN (WCSS) and
 * APSS (A53SS) register spaces; those are left out on purpose so the
 * audio DSP cannot reach the other subsystems or the application cores.
 */
static const struct fw_rsc_devmem lpass_mem_res[] = {
	{ .name = "tcsr_mutex", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x340000, .pa = 0x340000, .len = 0x40000, },
	{ .name = "tcsr0", .flags = IOMMU_READ,
		.da = 0x3c0000, .pa = 0x3c0000, .len = 0xb000, },
	{ .name = "tcsr1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3cb000, .pa = 0x3cb000, .len = 0x1000, },
	{ .name = "tcsr2", .flags = IOMMU_READ,
		.da = 0x3cc000, .pa = 0x3cc000, .len = 0x1d000, },
	{ .name = "tcsr3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3e9000, .pa = 0x3e9000, .len = 0x1000, },
	{ .name = "tcsr4", .flags = IOMMU_READ,
		.da = 0x3ea000, .pa = 0x3ea000, .len = 0x6000, },
	{ .name = "tcsr5", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3f1000, .pa = 0x3f1000, .len = 0x1000, },
	{ .name = "tlmm", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x400000, .pa = 0x400000, .len = 0x800000, },
	/* 0x1412000 (GCC_TIC_CFG_AHB_CBCR, test interface) stays out */
	{ .name = "gcc0", .flags = IOMMU_READ,
		.da = 0x1400000, .pa = 0x1400000, .len = 0x12000, },
	{ .name = "gcc1", .flags = IOMMU_READ,
		.da = 0x1413000, .pa = 0x1413000, .len = 0x4000, },
	{ .name = "gcc2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1417000, .pa = 0x1417000, .len = 0x2000, },
	{ .name = "gcc3", .flags = IOMMU_READ,
		.da = 0x1419000, .pa = 0x1419000, .len = 0x6000, },
	{ .name = "gcc4", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x141f000, .pa = 0x141f000, .len = 0x1000, },
	{ .name = "gcc5", .flags = IOMMU_READ,
		.da = 0x1420000, .pa = 0x1420000, .len = 0x1000, },
	{ .name = "gcc6", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1421000, .pa = 0x1421000, .len = 0x1000, },
	{ .name = "gcc7", .flags = IOMMU_READ,
		.da = 0x1422000, .pa = 0x1422000, .len = 0x6000, },
	{ .name = "gcc8", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1428000, .pa = 0x1428000, .len = 0x1000, },
	{ .name = "gcc9", .flags = IOMMU_READ,
		.da = 0x1429000, .pa = 0x1429000, .len = 0x7000, },
	{ .name = "gcc10", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1430000, .pa = 0x1430000, .len = 0x10000, },
	{ .name = "gcc11", .flags = IOMMU_READ,
		.da = 0x1440000, .pa = 0x1440000, .len = 0x3000, },
	{ .name = "gcc12", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1443000, .pa = 0x1443000, .len = 0x1000, },
	{ .name = "gcc13", .flags = IOMMU_READ,
		.da = 0x1444000, .pa = 0x1444000, .len = 0x3000, },
	{ .name = "gcc14", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1447000, .pa = 0x1447000, .len = 0x1000, },
	{ .name = "gcc15", .flags = IOMMU_READ,
		.da = 0x1448000, .pa = 0x1448000, .len = 0xc000, },
	{ .name = "gcc16", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1454000, .pa = 0x1454000, .len = 0x2000, },
	{ .name = "gcc17", .flags = IOMMU_READ,
		.da = 0x1456000, .pa = 0x1456000, .len = 0xc000, },
	{ .name = "gcc18", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1462000, .pa = 0x1462000, .len = 0x1000, },
	{ .name = "gcc19", .flags = IOMMU_READ,
		.da = 0x1463000, .pa = 0x1463000, .len = 0x12000, },
	{ .name = "gcc20", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1475000, .pa = 0x1475000, .len = 0x1000, },
	{ .name = "gcc21", .flags = IOMMU_READ,
		.da = 0x1476000, .pa = 0x1476000, .len = 0x17a000, },
	{ .name = "system_noc0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x18a3000, .pa = 0x18a3000, .len = 0x1000, },
	{ .name = "system_noc1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x18a8000, .pa = 0x18a8000, .len = 0x1000, },
	{ .name = "crypto_bam0", .flags = IOMMU_READ,
		.da = 0x1b04000, .pa = 0x1b04000, .len = 0x1000, },
	{ .name = "crypto_bam1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b05000, .pa = 0x1b05000, .len = 0x1000, },
	{ .name = "crypto_bam2", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b08000, .pa = 0x1b08000, .len = 0x1000, },
	{ .name = "crypto0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b3a000, .pa = 0x1b3a000, .len = 0x1000, },
	{ .name = "crypto1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1b3d000, .pa = 0x1b3d000, .len = 0x1000, },
	{ .name = "sec_ctrl", .flags = IOMMU_READ,
		.da = 0x1b40000, .pa = 0x1b40000, .len = 0x7000, },
	{ .name = "spmi_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1c00000, .pa = 0x1c00000, .len = 0x30000, },
	{ .name = "pmic_arb", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x1c40000, .pa = 0x1c40000, .len = 0x10000, },
	{ .name = "pmic_arb_mgpi", .flags = IOMMU_READ,
		.da = 0x1c60000, .pa = 0x1c60000, .len = 0x81000, },
	{ .name = "pmic_obs", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x3e00000, .pa = 0x3e00000, .len = 0x100000, },
	{ .name = "spmi_pic", .flags = IOMMU_READ,
		.da = 0x3f00000, .pa = 0x3f00000, .len = 0xa0000, },
	{ .name = "mapss0", .flags = IOMMU_READ,
		.da = 0x4400000, .pa = 0x4400000, .len = 0xb000, },
	{ .name = "mapss1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x440b000, .pa = 0x440b000, .len = 0x1000, },
	{ .name = "mapss2", .flags = IOMMU_READ,
		.da = 0x440c000, .pa = 0x440c000, .len = 0x34000, },
	{ .name = "prng_cm", .flags = IOMMU_READ,
		.da = 0x4450000, .pa = 0x4450000, .len = 0x1000, },
	{ .name = "prng_ee4", .flags = IOMMU_READ,
		.da = 0x4455000, .pa = 0x4455000, .len = 0x1000, },
	{ .name = "prng_ee9", .flags = IOMMU_READ,
		.da = 0x445a000, .pa = 0x445a000, .len = 0x1000, },
	{ .name = "ddrss", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x450e000, .pa = 0x450e000, .len = 0x1000, },
	{ .name = "rpm_msg_ram0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x45f2000, .pa = 0x45f2000, .len = 0x1000, },
	{ .name = "rpm_msg_ram1", .flags = IOMMU_READ,
		.da = 0x45f6000, .pa = 0x45f6000, .len = 0x1000, },
	{ .name = "usb3", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x4e00000, .pa = 0x4e00000, .len = 0xd000, },
	{ .name = "mdss", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x5e00000, .pa = 0x5e00000, .len = 0xc0000, },
	{ .name = "qdss_csr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8001000, .pa = 0x8001000, .len = 0x1000, },
	{ .name = "qdss_stm_cfg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8002000, .pa = 0x8002000, .len = 0x1000, },
	{ .name = "qdss_dl_slv_fun", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8005000, .pa = 0x8005000, .len = 0x1000, },
	{ .name = "qdss_in_fun0", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8041000, .pa = 0x8041000, .len = 0x1000, },
	{ .name = "qdss_in_fun1", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8042000, .pa = 0x8042000, .len = 0x1000, },
	{ .name = "qdss_merg_fun", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8045000, .pa = 0x8045000, .len = 0x1000, },
	{ .name = "qdss_repl", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8046000, .pa = 0x8046000, .len = 0x1000, },
	{ .name = "qdss_etr", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8048000, .pa = 0x8048000, .len = 0x1000, },
	{ .name = "lpass_lpi_dbg", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x8a20000, .pa = 0x8a20000, .len = 0x20000, },
	{ .name = "stm", .flags = IOMMU_WRITE,
		.da = 0xe000000, .pa = 0xe000000, .len = 0x1000000, },
	{ .name = "smem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x46000000, .pa = 0x46000000, .len = 0x200000, },
};

DEFINE_RESOURCE_TABLE(LPASS, ARRAY_SIZE(lpass_mem_res));

static TEE_Result lpass_fw_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timeout = 0;

	if (!base)
		return TEE_ERROR_GENERIC;

	/* Boot from the firmware entry through the EFUSE EVB register */
	io_setbits32(base + LPASS_EFUSE_Q6SS_EVB_SEL, BIT(0));
	/* EVB_ADDR.ADDR (bits 27:4) holds the entry address >> 4 */
	io_write32(base + LPASS_EFUSE_Q6SS_EVB_ADDR,
		   (data->fw_base >> 4) & EVB_ADDR_MASK);
	dsb();

	io_setbits32(base + LPASS_QDSP6SS_BOOT_CORE_START, BIT(0));
	io_write32(base + LPASS_QDSP6SS_BOOT_CMD, BIT(0));

	timeout = timeout_init_us(BOOT_FSM_TIMEOUT_US);
	while (!(io_read32(base + LPASS_QDSP6SS_BOOT_STATUS) & BIT(0))) {
		if (timeout_elapsed(timeout)) {
			EMSG("ADSP boot FSM timed out");
			return TEE_ERROR_TIMEOUT;
		}
		udelay(5);
	}

	return TEE_SUCCESS;
}

static TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data)
{
	return qcom_clock_pas_reset(data->clk_group);
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

	return get_mem_rsc(rt, rt_size, &table, &header, lpass_mem_res,
			   LPASS_RESOURCE_TABLE_HEADER_SIZE,
			   LPASS_RESOURCE_TABLE_SIZE);
}

const struct qcom_pas_ops lpass_ops = {
	.fw_start = lpass_fw_start,
	.fw_shutdown = lpass_fw_shutdown,
	.get_resource_table = lpass_get_resource_table,
};
