// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/delay.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <string.h>

#include "pas.h"

/*QDSP6SS register offsets*/
#define RST_EVB_REG			0x10
#define CORE_START_REG			0x400
#define BOOT_CMD_REG			0x404
#define BOOT_STATUS_REG			0x408
#define RET_CFG_REG			0x1C

#define QDSP6SS_XO_CBCR			0x38
#define QDSP6SS_CORE_CBCR		0x20
#define QDSP6SS_SLEEP_CBCR		0x3c
#define LPASS_BOOT_CORE_START		BIT(0)
#define LPASS_BOOT_CMD_START		BIT(0)
#define LPASS_EFUSE_Q6SS_EVB_SEL	0x0

#define BOOT_FSM_TIMEOUT		10000

#if defined(PLATFORM_FLAVOR_kodiak)
#define WPSS_DEVMEM_REGIONS		2
static struct resource_table wpss_rt = {
	.ver = 1,
	.num = WPSS_DEVMEM_REGIONS,
	.offset[WPSS_DEVMEM_REGIONS] = 0,
};

static struct fw_rsc_hdr wpss_hdr = {
	.type = RSC_DEVMEM,
};

static struct fw_rsc_devmem wlan_fw_mem = {
	.name = "wlan_fw_mem",
	.da = 0x80c00000,
	.pa = 0x80c00000,
	.len = 0xc00000,
	.flags = IOMMU_READ | IOMMU_WRITE,
};

static struct fw_rsc_devmem wlan_ce_mem = {
	.name = "wlan_ce_mem",
	.da = 0x004cd000,
	.pa = 0x004cd000,
	.len = 0x1000,
	.flags = IOMMU_READ | IOMMU_WRITE,
};
#else
static struct resource_table wpss_rt;
static struct fw_rsc_hdr;
static struct fw_rsc_devmem wlan_fw_mem;
static struct fw_rsc_devmem wlan_ce_mem;
#endif

void wpss_dsp_get_rsc_table(struct resource_table *rt, size_t *rt_size)
{
	size_t expected_rt_size;
	uint8_t *rt_ptr = (uint8_t *)rt;
	uint32_t offset = 0;

	if (!wpss_rt.num)
		return;

	expected_rt_size = sizeof(wpss_rt) + wpss_rt.num *
			   (sizeof(*wpss_rt.offset) + sizeof(wpss_hdr) +
			    sizeof(struct fw_rsc_devmem));
	if (!rt || *rt_size < expected_rt_size) {
		*rt_size = expected_rt_size;
		return;
	}

	memcpy(rt, &wpss_rt, sizeof(wpss_rt));
	offset += sizeof(wpss_rt) + wpss_rt.num * sizeof(*wpss_rt.offset);

	rt->offset[0] = offset;
	memcpy(rt_ptr + offset, &wpss_hdr, sizeof(wpss_hdr));
	offset += sizeof(wpss_hdr);
	memcpy(rt_ptr + offset, &wlan_fw_mem, sizeof(wlan_fw_mem));
	offset += sizeof(wlan_fw_mem);

	rt->offset[1] = offset;
	memcpy(rt_ptr + offset, &wpss_hdr, sizeof(wpss_hdr));
	offset += sizeof(wpss_hdr);
	memcpy(rt_ptr + offset, &wlan_ce_mem, sizeof(wlan_ce_mem));
}

TEE_Result wpss_dsp_start(struct qcom_pas_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, 0x500);
	uint32_t val;
	uint64_t timer;

	/* Enable the XO clock */
	io_write32(base + QDSP6SS_XO_CBCR, 1);

	/* Enable the QDSP6SS sleep clock */
	io_write32(base + QDSP6SS_SLEEP_CBCR, 1);

	/* Enable the QDSP6 core clock */
	io_write32(base + QDSP6SS_CORE_CBCR, 1);

	/* Program boot address */
	io_write32(base + RST_EVB_REG, data->fw_base >> 4);

	/* Flush configuration */
	dsb();

	/* De-assert QDSP6 stop core. QDSP6 will execute after out of reset */
	io_write32(base + CORE_START_REG, LPASS_BOOT_CORE_START);

	/* Trigger boot FSM to start QDSP6 */
	io_write32(base + BOOT_CMD_REG, LPASS_BOOT_CMD_START);

	/* Wait for core to come out of reset */
	timer = timeout_init_us(BOOT_FSM_TIMEOUT);
	do {
		val = io_read32(base + BOOT_STATUS_REG);
		if (val & BIT(0))
			break;
		if (timeout_elapsed(timer))
			break;
		udelay(10);
	} while (1);

	if ((val & BIT(0)) == 0) {
		EMSG("Timed out waiting for DSP to boot :(");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}
