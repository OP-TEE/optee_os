/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_COMMON_H__
#define __QFPROM_COMMON_H__

#define QFPROM_GATELAST_VAL                     0x1

#define QFPROM_GATELAST_SHFT                    11
#define QFPROM_TRIPPT_SEL_SHFT                  8
#define QFPROM_ACCEL_SHFT                       0

#define QFPROM_ACCEL_VALUE \
	((QFPROM_GATELAST_VAL << QFPROM_GATELAST_SHFT) | \
	 (QFPROM_TRIPPT_SEL_VAL << QFPROM_TRIPPT_SEL_SHFT) | \
	 (QFPROM_ACCEL_VAL << QFPROM_ACCEL_SHFT))

#define QFPROM_ACCEL_RESET_VALUE \
	(0x1 << QFPROM_GATELAST_SHFT)

#define QFPROM_RAW_TO_CORR(raw_addr) \
	((raw_addr) + (QFPROM_CORR_BASE - QFPROM_RAW_BASE))

#endif /* __QFPROM_COMMON_H__ */
