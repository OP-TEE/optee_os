/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_IRIS_H
#define PAS_IRIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
#define SS_TZ_CP_VP8_SECURE_OVERRIDE_DEC	0x000c2098
#define SS_TZ_CP_VP9_SECURE_OVERRIDE_DEC	0x000c209c

/*
 * struct pas_iris_write : one write of the secure session settings.
 *
 * @reg:   register, as an offset from IRIS_BASE
 * @val:   value written
 * @check: read the register back and fail unless it holds @val
 */
struct pas_iris_write {
	uint32_t reg;
	uint32_t val;
	bool check;
};

#define PAS_IRIS_WRITE(r, v)	{ .reg = (r), .val = (v) }
#define PAS_IRIS_CHECK(r, v)	{ .reg = (r), .val = (v), .check = true }

/* struct pas_iris_seq : @count writes from @writes, in order */
struct pas_iris_seq {
	const struct pas_iris_write *writes;
	size_t count;
};

/*
 * struct pas_iris_cfg : platform settings of an iris subsystem.
 *
 * The iris core writes the secure session settings shared by the cores with
 * an SS_TZ block, in this order: clear the CP override and every stream ID
 * secure override, set the secure thresholds, @before_checks, set and read
 * back the secure overrides of stream IDs 0x1 and 0x7, then @after_checks.
 *
 * @before_checks: platform writes before the stream ID 0x1 and 0x7 overrides
 * @after_checks:  platform writes after them
 * @every_release: write the settings before every release on resume too,
 *                 not only at start
 */
struct pas_iris_cfg {
	struct pas_iris_seq before_checks;
	struct pas_iris_seq after_checks;
	bool every_release;
};

/*
 * Firmware operations of an iris video codec subsystem, whose registers
 * are mapped from the struct qcom_pas_data base (IRIS_BASE). The
 * platform settings come from its iris member, NULL when there are none.
 */
extern const struct qcom_pas_ops pas_iris_ops;

#endif /* PAS_IRIS_H */
