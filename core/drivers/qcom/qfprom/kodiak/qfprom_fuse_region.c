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

#define QFPROM_STD_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_NONE, true, idx)

#define QFPROM_FEC_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_63_56, true, idx)

#define QFPROM_PRIVATE_REGION(name, sz, idx) \
	QFPROM_REGION_ENTRY(name, sz, QFPROM_FEC_NONE, false, idx)

const struct qfprom_region_info region_data[] = {
	QFPROM_STD_REGION(LCM, 1, 1),
	QFPROM_PRIVATE_REGION(PRI_KEY_DERIVATION_KEY, 4, 2),
	QFPROM_STD_REGION(MRC_2_0, 2, 4),
	QFPROM_STD_REGION(PTE, 5, 5),
	QFPROM_STD_REGION(READ_PERMISSION, 1, 6),
	QFPROM_STD_REGION(WRITE_PERMISSION, 1, 7),
	QFPROM_STD_REGION(FEC_ENABLES, 1, 8),
	QFPROM_STD_REGION(OEM_CONFIG, 3, 9),
	QFPROM_STD_REGION(FEATURE_CONFIG_M, 5, 10),
	QFPROM_STD_REGION(FEATURE_CONFIG_NM, 4, 11),
	QFPROM_STD_REGION(ANTI_ROLLBACK_1, 1, 12),
	QFPROM_STD_REGION(ANTI_ROLLBACK_2, 1, 13),
	QFPROM_STD_REGION(ANTI_ROLLBACK_3, 1, 14),
	QFPROM_STD_REGION(ANTI_ROLLBACK_4, 1, 15),
	QFPROM_STD_REGION(ANTI_ROLLBACK_5, 1, 16),
	QFPROM_STD_REGION(PK_HASH_0, 6, 17),
	QFPROM_STD_REGION(CALIBRATION, 25, 18),
	QFPROM_STD_REGION(MEMORY_CONFIGURATION, 120, 19),
	QFPROM_FEC_REGION(QC_SPARE_20, 1, 20),
	QFPROM_FEC_REGION(QC_SPARE_21, 1, 21),
	QFPROM_FEC_REGION(OEM_IMAGE_ENCRYPTION_KEY, 3, 22),
	QFPROM_FEC_REGION(OEM_SECURE_BOOT, 2, 23),
	QFPROM_FEC_REGION(SEC_KEY_DERIVATION_KEY, 5, 24),
	QFPROM_FEC_REGION(IMAGE_ENCRYPTION_KEY_1, 3, 26),
	QFPROM_FEC_REGION(USER_KEY_DERIVATION_KEY, 5, 27),
	QFPROM_STD_REGION(OEM_SPARE_28, 2, 28),
	QFPROM_STD_REGION(OEM_SPARE_29, 2, 29),
	QFPROM_STD_REGION(OEM_SPARE_30, 2, 30),
	QFPROM_STD_REGION(OEM_SPARE_31, 2, 31),
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
	.name = "Kodiak",
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
