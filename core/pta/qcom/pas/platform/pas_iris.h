/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_IRIS_H
#define PAS_IRIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types_ext.h>

#include "pas_subsys.h"

/* SS_TZ block secure session registers, as offsets from IRIS_BASE */
#define SS_TZ_SEC_THRESHOLD_HEVC		0x000c2004
#define SS_TZ_SEC_THRESHOLD_H264		0x000c2008
#define SS_TZ_SEC_THRESHOLD_MP2			0x000c200c
#define SS_TZ_SEC_THRESHOLD_NON_VCL_HEVC	0x000c2018
#define SS_TZ_SEC_THRESHOLD_NON_VCL_H264	0x000c201c
#define SS_TZ_SEC_THRESHOLD_NON_VCL_MP2		0x000c2020
#define SS_TZ_SEC_DS_THRESHOLD			0x000c2024
#define SS_TZ_SEC_SID_0_SECURE_OVERRIDE		0x000c2040
#define SS_TZ_SEC_SID_1_SECURE_OVERRIDE		0x000c2044
#define SS_TZ_SEC_SID_2_SECURE_OVERRIDE		0x000c2048
#define SS_TZ_SEC_SID_3_SECURE_OVERRIDE		0x000c204c
#define SS_TZ_SEC_SID_4_SECURE_OVERRIDE		0x000c2050
#define SS_TZ_SEC_SID_5_SECURE_OVERRIDE		0x000c2054
#define SS_TZ_SEC_SID_6_SECURE_OVERRIDE		0x000c2058
#define SS_TZ_SEC_SID_7_SECURE_OVERRIDE		0x000c205c
#define SS_TZ_SEC_SID_8_SECURE_OVERRIDE		0x000c2060
#define SS_TZ_SEC_SID_9_SECURE_OVERRIDE		0x000c2064
#define SS_TZ_SEC_SID_A_SECURE_OVERRIDE		0x000c2068
#define SS_TZ_SEC_SID_B_SECURE_OVERRIDE		0x000c206c
#define SS_TZ_SEC_SID_C_SECURE_OVERRIDE		0x000c2070
#define SS_TZ_SEC_SID_D_SECURE_OVERRIDE		0x000c2074
#define SS_TZ_SEC_SID_E_SECURE_OVERRIDE		0x000c2078
#define SS_TZ_SEC_SID_F_SECURE_OVERRIDE		0x000c207c
#define SS_TZ_SEC_SID_10_SECURE_OVERRIDE	0x000c2080
#define SS_TZ_CP_OVERRIDE			0x000c2090

/*
 * struct pas_iris_seed : seed segment of the video firmware image being
 * loaded, see pas_iris.c.
 *
 * @valid:  set at PTA_QCOM_PAS_INIT_IMAGE for the image being loaded
 * @offset: offset of the seed from the start of the firmware region
 * @size:   size of the seed, 0 when the image has none
 */
struct pas_iris_seed {
	bool valid;
	uint64_t offset;
	size_t size;
};

/*
 * struct pas_iris_data : subsystem_data of an iris subsystem.
 *
 * @seed: seed of the image being loaded
 */
struct pas_iris_data {
	struct pas_iris_seed seed;
};

/*
 * Helpers for the iris firmware operations of each SoC. The registers are
 * mapped from the struct qcom_pas_data base (IRIS_BASE) and subsystem_data
 * points to the struct pas_iris_data of the subsystem; @base is IRIS_BASE
 * mapped.
 */

/* fw_init_image operation: find the seed of the image being loaded */
TEE_Result pas_iris_init_image(struct qcom_pas_data *data,
			       const struct pas_metadata *metadata,
			       const struct elf_info *e_info);

/* Fail unless the loaded firmware fits below the CP non-pixel window */
TEE_Result pas_iris_check_fw_size(struct qcom_pas_data *data);

/* At start, fill the seed of the loaded image; checks the firmware size */
TEE_Result pas_iris_fill_seed(struct qcom_pas_data *data);

/*
 * Program the CP layout for a firmware of @fw_size bytes, which must have
 * passed pas_iris_check_fw_size()
 */
void pas_iris_set_cp_layout(vaddr_t base, size_t fw_size);

/* Take the core out of reset */
void pas_iris_release_core(vaddr_t base);

/* fw_shutdown operation: hold the core in reset */
TEE_Result pas_iris_fw_shutdown(struct qcom_pas_data *data);

/* SS_TZ block writes, for the secure session sequence of a SoC */

/* Clear the CP override and the overrides of stream IDs 0x0 to 0x10 */
void pas_iris_clear_overrides(vaddr_t base);

/* Set the DS, HEVC, H264 and MP2 secure thresholds */
void pas_iris_set_thresholds(vaddr_t base);

/* Set the non-VCL secure thresholds */
void pas_iris_set_non_vcl_thresholds(vaddr_t base);

/* Write @val to @reg and fail unless it reads back */
TEE_Result pas_iris_write_check(vaddr_t base, uint32_t reg, uint32_t val);

#endif /* PAS_IRIS_H */
