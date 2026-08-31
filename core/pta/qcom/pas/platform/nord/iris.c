// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <stdint.h>
#include <trace.h>

#include "iris.h"

#define WRAPPER_TZ_XTSS_SW_RESET	0x1000
#define WRAPPER_XTSS_SW_RESET_BIT	BIT(0)

#define WRAPPER_TZ_SEC_0_SID		0x10c0
#define WRAPPER_TZ_SEC_1_SID		0x10c4
#define WRAPPER_TZ_SEC_2_SID		0x10c8
#define WRAPPER_TZ_SEC_DEFAULT_SID	0x10cc

#define WRAPPER_TZ_SEC_0_START_ADDR	0x1040
#define WRAPPER_TZ_SEC_0_END_ADDR	0x1044
#define WRAPPER_TZ_SEC_1_START_ADDR	0x1048
#define WRAPPER_TZ_SEC_1_END_ADDR	0x104c
#define WRAPPER_TZ_SEC_2_START_ADDR	0x1050
#define WRAPPER_TZ_SEC_2_END_ADDR	0x1054

#define WRAPPER_SEC_CSR1		0x1084
#define WRAPPER_SEC_CSR1_TUNNEL_BIT	BIT(0)
#define WRAPPER_SEC_CSR7		0x109c

#define IRIS_CORE_TZ_OFFSET		0x1000
#define IRIS_NUMBER_OF_CORES		2

#define CORE_TZ_SEC_THRESHOLD_HEVC	0x4
#define CORE_TZ_SEC_THRESHOLD_H264	0x8
#define CORE_TZ_SEC_THRESHOLD_MP2	0xc
#define CORE_TZ_SEC_THRESHOLD_NON_VCL_HEVC	0x18
#define CORE_TZ_SEC_THRESHOLD_NON_VCL_H264	0x1c
#define CORE_TZ_SEC_THRESHOLD_NON_VCL_MP2	0x20
#define CORE_TZ_SEC_DS_THRESHOLD	0x24
#define CORE_TZ_SEC_THRESHOLD_AV1	0x2c

#define CORE_TZ_SEC_SID_VPP_BASE	0x110
#define CORE_TZ_SEC_SID_BSE_BASE	0x150
#define CORE_TZ_SEC_SID_CCE_BASE	0x190

#define CORE_TZ_SID_VPP_WORDS		2
#define CORE_TZ_SID_BSE_WORDS		2
#define CORE_TZ_SID_CCE_WORDS		3
#define CORE_TZ_SID_NUM_PARTITIONS	8

#define IRIS_SCIBCMDARG3_OFFSET		0x000a006c

static const uint32_t iris_cce_sid_table[CORE_TZ_SID_NUM_PARTITIONS]
					[CORE_TZ_SID_CCE_WORDS] = {
	{ 0x04201084, 0x04010082, 0x00000000 },
	{ 0x042098c6, 0x041108c2, 0x00008421 },
	{ 0x14a4318c, 0x1485218a, 0x00042108 },
	{ 0x14a4b9ce, 0x149529ca, 0x0004a529 },
	{ 0x25285294, 0x25094292, 0x00084210 },
	{ 0x2528dad6, 0x25194ad2, 0x0008c631 },
	{ 0x35ac739c, 0x358d639a, 0x000c6318 },
	{ 0x35acfbde, 0x359d6bda, 0x000ce739 },
};

static const uint32_t iris_bse_sid_table[CORE_TZ_SID_NUM_PARTITIONS]
					[CORE_TZ_SID_BSE_WORDS] = {
	{ 0x00021084, 0x00020000 },
	{ 0x021318c6, 0x00008421 },
	{ 0x1086318c, 0x00062108 },
	{ 0x129739ce, 0x0004a529 },
	{ 0x210a5294, 0x000a4210 },
	{ 0x231b5ad6, 0x0008c631 },
	{ 0x318e739c, 0x000e6318 },
	{ 0x339f7bde, 0x000ce739 },
};

static const uint32_t iris_vpp_sid_table[CORE_TZ_SID_NUM_PARTITIONS]
					[CORE_TZ_SID_VPP_WORDS] = {
	{ 0x06000084, 0x00000063 },
	{ 0x0a1084c6, 0x000084a5 },
	{ 0x1684218c, 0x0004216b },
	{ 0x1a94a5ce, 0x0004a5ad },
	{ 0x27084294, 0x00084273 },
	{ 0x2b18c6d6, 0x0008c6b5 },
	{ 0x378c639c, 0x000c637b },
	{ 0x3b9ce7de, 0x000ce7bd },
};

struct iris_mem_region {
	uint32_t start_reg;
	uint32_t end_reg;
	uint32_t start;
	uint32_t size;
};

static const struct iris_mem_region iris_mem_regions[] = {
	{ WRAPPER_TZ_SEC_0_START_ADDR, WRAPPER_TZ_SEC_0_END_ADDR,
	  0x00000000, 0x01000000 },
	{ WRAPPER_TZ_SEC_1_START_ADDR, WRAPPER_TZ_SEC_1_END_ADDR,
	  0x01000000, 0x24800000 },
	{ WRAPPER_TZ_SEC_2_START_ADDR, WRAPPER_TZ_SEC_2_END_ADDR,
	  0x25800000, 0xda600000 },
};

static void iris_program_core_sid_tables(vaddr_t core_base)
{
	unsigned int part = 0;
	unsigned int word = 0;
	vaddr_t addr = 0;

	io_write32(core_base + CORE_TZ_SEC_DS_THRESHOLD,           3);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_HEVC,         1344);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_H264,         270);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_MP2,          46);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_AV1,          1280);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_NON_VCL_HEVC, 3800);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_NON_VCL_H264, 12600);
	io_write32(core_base + CORE_TZ_SEC_THRESHOLD_NON_VCL_MP2,  1600);

	addr = core_base + CORE_TZ_SEC_SID_CCE_BASE;
	for (part = 0; part < CORE_TZ_SID_NUM_PARTITIONS; part++) {
		for (word = 0; word < CORE_TZ_SID_CCE_WORDS; word++) {
			io_write32(addr, iris_cce_sid_table[part][word]);
			addr += sizeof(uint32_t);
		}
	}

	addr = core_base + CORE_TZ_SEC_SID_BSE_BASE;
	for (part = 0; part < CORE_TZ_SID_NUM_PARTITIONS; part++) {
		for (word = 0; word < CORE_TZ_SID_BSE_WORDS; word++) {
			io_write32(addr, iris_bse_sid_table[part][word]);
			addr += sizeof(uint32_t);
		}
	}

	addr = core_base + CORE_TZ_SEC_SID_VPP_BASE;
	for (part = 0; part < CORE_TZ_SID_NUM_PARTITIONS; part++) {
		for (word = 0; word < CORE_TZ_SID_VPP_WORDS; word++) {
			io_write32(addr, iris_vpp_sid_table[part][word]);
			addr += sizeof(uint32_t);
		}
	}
}

static TEE_Result iris_program_sec_sid_registers(vaddr_t iris_base)
{
	vaddr_t top_base = iris_base + IRIS_WRAPPER_TOP_REG_BASE;
	vaddr_t tz_base = iris_base + IRIS_WRAPPER_TZ_REG_BASE;
	vaddr_t core0_base = iris_base + IRIS_CORE0_TZ_REG_BASE;
	unsigned int core = 0;

	for (core = 0; core < IRIS_NUMBER_OF_CORES; core++)
		iris_program_core_sid_tables(core0_base +
					     core * IRIS_CORE_TZ_OFFSET);

	io_write32(iris_base + IRIS_SCIBCMDARG3_OFFSET, 0xbeef0001);

	io_write32(tz_base + WRAPPER_TZ_SEC_0_SID,      0x0198a422);
	io_write32(tz_base + WRAPPER_TZ_SEC_1_SID,      0x00006208);
	io_write32(tz_base + WRAPPER_TZ_SEC_2_SID,      0x00000000);
	io_write32(tz_base + WRAPPER_TZ_SEC_DEFAULT_SID, 0x00000000);

	io_write32(top_base + WRAPPER_SEC_CSR1, WRAPPER_SEC_CSR1_TUNNEL_BIT);
	io_write32(top_base + WRAPPER_SEC_CSR7, 0x1);

	return TEE_SUCCESS;
}

static void iris_program_mem_regions(vaddr_t tz_base)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(iris_mem_regions); i++) {
		const struct iris_mem_region *r = &iris_mem_regions[i];

		io_write32(tz_base + r->start_reg, r->start);
		io_write32(tz_base + r->end_reg,   r->start + r->size);
	}
}

static bool iris_resumed;

static TEE_Result iris_fw_start(struct qcom_pas_data *data)
{
	vaddr_t iris_base = 0;
	vaddr_t tz_base = 0;
	TEE_Result res = TEE_SUCCESS;

	iris_base = io_pa_or_va(&data->base, data->size);
	if (!iris_base)
		return TEE_ERROR_GENERIC;

	tz_base = iris_base + IRIS_WRAPPER_TZ_REG_BASE;

	if (!data->fw_base) {
		EMSG("iris: FW not loaded");
		return TEE_ERROR_NO_DATA;
	}

	udelay(IRIS_CLK_SETTLE_US);

	if (!(io_read32(tz_base + WRAPPER_TZ_XTSS_SW_RESET) &
	      WRAPPER_XTSS_SW_RESET_BIT)) {
		DMSG("iris: subsystem already running, skipping bring-up");
		return TEE_SUCCESS;
	}

	iris_program_mem_regions(tz_base);

	res = iris_program_sec_sid_registers(iris_base);
	if (res)
		return res;

	io_write32(tz_base + WRAPPER_TZ_XTSS_SW_RESET, 0);

	iris_resumed = true;

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_shutdown(struct qcom_pas_data *data)
{
	vaddr_t iris_base = 0;
	vaddr_t tz_base = 0;
	uint32_t reg = 0;

	iris_base = io_pa_or_va(&data->base, data->size);
	if (!iris_base)
		return TEE_ERROR_GENERIC;

	tz_base = iris_base + IRIS_WRAPPER_TZ_REG_BASE;

	if (iris_resumed) {
		reg = io_read32(tz_base + WRAPPER_TZ_XTSS_SW_RESET);
		reg |= WRAPPER_XTSS_SW_RESET_BIT;
		io_write32(tz_base + WRAPPER_TZ_XTSS_SW_RESET, reg);
	} else {
		EMSG("iris: shutdown not in resumed state");
	}

	iris_resumed = false;

	return TEE_SUCCESS;
}

static TEE_Result iris_fw_set_state(struct qcom_pas_data *data, bool power_on)
{
	vaddr_t iris_base = 0;
	vaddr_t tz_base = 0;
	uint32_t reg = 0;

	if (!power_on) {
		if (iris_resumed) {
			iris_base = io_pa_or_va(&data->base, data->size);
			if (!iris_base)
				return TEE_ERROR_GENERIC;
			tz_base = iris_base + IRIS_WRAPPER_TZ_REG_BASE;
			reg = io_read32(tz_base + WRAPPER_TZ_XTSS_SW_RESET);
			reg |= WRAPPER_XTSS_SW_RESET_BIT;
			io_write32(tz_base + WRAPPER_TZ_XTSS_SW_RESET, reg);
			iris_resumed = false;
		} else {
			EMSG("iris: cannot SUSPEND, not in resumed state");
		}
		return TEE_SUCCESS;
	}

	return iris_fw_start(data);
}

const struct qcom_pas_ops iris_ops = {
	.fw_start = iris_fw_start,
	.fw_shutdown = iris_fw_shutdown,
	.fw_set_state = iris_fw_set_state,
};
