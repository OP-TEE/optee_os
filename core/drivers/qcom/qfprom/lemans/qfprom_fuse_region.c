// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <qfprom_target.h>

#include "qfprom_priv.h"

#define QFPROM_REGION_ENTRY(name, sz, fec, readable, idx) \
	{ \
		.region_name = QFPROM_##name##_REGION, \
		.size = (sz), \
		.fec_type = (fec), \
		.raw_base_addr = name##_ADDR, \
		.corr_base_addr = QFPROM_RAW_TO_CORR(name##_ADDR), \
		.read_perm_mask = name##_PERM_MASK, \
		.write_perm_mask = name##_PERM_MASK, \
		.perm_reg_type = QFPROM_ROW_LSB, \
		.read_allowed = (readable), \
		.region_index = (idx), \
	}

#define QFPROM_REGION_ENTRY_MSB(name, sz, fec, readable, idx) \
	{ \
		.region_name = QFPROM_##name##_REGION, \
		.size = (sz), \
		.fec_type = (fec), \
		.raw_base_addr = name##_ADDR, \
		.corr_base_addr = QFPROM_RAW_TO_CORR(name##_ADDR), \
		.read_perm_mask = name##_PERM_MASK, \
		.write_perm_mask = name##_PERM_MASK, \
		.perm_reg_type = QFPROM_ROW_MSB, \
		.read_allowed = (readable), \
		.region_index = (idx), \
	}

#define QFPROM_STD_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_NONE, true, idx)

#define QFPROM_FEC_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_63_56, true, idx)

#define QFPROM_FEC_REGION_MSB(name, sz, idx) \
	QFPROM_REGION_ENTRY_MSB(name, sz, QFPROM_FEC_63_56, true, idx)

#define QFPROM_PRIVATE_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_NONE, false, idx)

#define QFPROM_STD_REGION_MSB(name, sz, idx) \
	QFPROM_REGION_ENTRY_MSB(name, sz, QFPROM_FEC_NONE, true, idx)

const struct qfprom_region_info region_data[] = {
	QFPROM_STD_REGION(LCM, 1, 1),
	QFPROM_PRIVATE_REGION(PRI_KEY_DERIVATION_KEY, 4, 2),
	QFPROM_STD_REGION(MRC_2_0, 2, 3),
	QFPROM_STD_REGION(PTE, 7, 4),
	QFPROM_STD_REGION(READ_PERMISSION, 1, 5),
	QFPROM_STD_REGION(WRITE_PERMISSION, 1, 6),
	QFPROM_STD_REGION(FEC_ENABLES, 1, 7),
	QFPROM_STD_REGION(OEM_CONFIG, 5, 8),
	QFPROM_STD_REGION(FEATURE_CONFIG_M, 8, 9),
	QFPROM_STD_REGION(FEATURE_CONFIG_NM, 5, 10),
	QFPROM_STD_REGION(ANTI_ROLLBACK_1, 1, 11),
	QFPROM_STD_REGION(ANTI_ROLLBACK_2, 1, 12),
	QFPROM_STD_REGION(ANTI_ROLLBACK_3, 1, 13),
	QFPROM_STD_REGION(ANTI_ROLLBACK_4, 1, 14),
	QFPROM_STD_REGION(ANTI_ROLLBACK_5, 1, 15),
	QFPROM_STD_REGION(ANTI_ROLLBACK_6, 1, 16),
	QFPROM_STD_REGION(ANTI_ROLLBACK_7, 1, 17),
	QFPROM_STD_REGION(ANTI_ROLLBACK_8, 1, 18),
	QFPROM_STD_REGION(ANTI_ROLLBACK_9, 1, 19),
	QFPROM_STD_REGION(ANTI_ROLLBACK_10, 1, 20),
	QFPROM_STD_REGION(ANTI_ROLLBACK_11, 1, 21),
	QFPROM_STD_REGION(ANTI_ROLLBACK_12, 1, 22),
	QFPROM_STD_REGION(ANTI_ROLLBACK_13, 1, 23),
	QFPROM_STD_REGION(PK_HASH_0, 8, 24),
	QFPROM_STD_REGION(CALIBRATION, 54, 25),
	QFPROM_STD_REGION(MEMORY_CONFIGURATION, 280, 26),
	QFPROM_FEC_REGION(QC_SPARE_20, 1, 27),
	QFPROM_FEC_REGION(QC_SPARE_21, 1, 28),
	QFPROM_FEC_REGION(OEM_IMAGE_ENCRYPTION_KEY, 3, 29),
	QFPROM_FEC_REGION(OEM_SECURE_BOOT, 2, 30),
	QFPROM_FEC_REGION_MSB(SEC_KEY_DERIVATION_KEY, 5, 31),
	QFPROM_FEC_REGION_MSB(IMAGE_ENCRYPTION_KEY_1, 3, 33),
	QFPROM_FEC_REGION_MSB(USER_KEY_DERIVATION_KEY, 5, 34),
	QFPROM_STD_REGION_MSB(OEM_SPARE_28, 2, 35),
	QFPROM_STD_REGION_MSB(OEM_SPARE_29, 2, 36),
	QFPROM_STD_REGION_MSB(OEM_SPARE_30, 2, 37),
	QFPROM_STD_REGION_MSB(OEM_SPARE_31, 2, 38),
	{
		QFPROM_LAST_REGION_DUMMY,
		0,
		QFPROM_FEC_NONE,
		0,
		0,
		0,
		0,
		QFPROM_ROW_LSB
	}
};

const size_t region_count = ARRAY_SIZE(region_data);

const struct qfprom_platform_config plat_config = {
	.name = "Lemans",
	.qfprom_raw_base = QFPROM_RAW_BASE,
	.qfprom_corr_base = QFPROM_CORR_BASE,
	.qfprom_size = QFPROM_SIZE,
	.region_data = region_data,
	.num_regions = ARRAY_SIZE(region_data),
	.read_perm_lsb_offset = QFPROM_READ_PERM_LSB_OFFSET,
	.read_perm_msb_offset = QFPROM_READ_PERM_MSB_OFFSET,
	.write_perm_lsb_offset = QFPROM_WRITE_PERM_LSB_OFFSET,
	.write_perm_msb_offset = QFPROM_WRITE_PERM_MSB_OFFSET,
};

const struct qfprom_platform_config *qfprom_get_platform_config(void)
{
	return &plat_config;
}
