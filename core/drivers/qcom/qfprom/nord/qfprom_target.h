/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_TARGET_H__
#define __QFPROM_TARGET_H__

#include <platform_config.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#define QFPROM_RAW_BASE                          0x360c0000
#define QFPROM_CORR_BASE                         0x360c8000
#define QFPROM_SIZE                              0x8000

#define QFPROM_RAW_TO_CORR(raw_addr) \
	((raw_addr) + (QFPROM_CORR_BASE - QFPROM_RAW_BASE))

#define QFPROM_FEC_EAR_OFFSET                    0x24
#define QFPROM_FEC_ESR_ERR_SEEN_BMSK             BIT(0)
#define QFPROM_FEC_EAR_ERR_ADDR_BMSK             0xFFFF

enum qfprom_region_name {
	QFPROM_LAST_REGION_DUMMY,
};

#define FEC_ENABLES_ADDR                        (QFPROM_RAW_BASE + 0x1a0)
#define PK_HASH_0_ADDR                           (QFPROM_RAW_BASE + 0x2a0)

#define SECURE_BOOT_APPS_OFFSET			0x0704
#define SECURE_BOOT_AUTH_EN_BMSK		0x20
#define SECURE_BOOT_USE_SERIAL_NUM_BMSK		0x40
#define QFPROM_ROOT_OF_TRUST_SENSE_OFFSET       0x0608
#define QFPROM_ROOT_OF_TRUST_SENSE_REG_COUNT    14

#define QFPROM_ROOT_OF_TRUST_BYTE_SIZE		48

#define OEM_ID_OFFSET				0x0800
#define OEM_ID_BMSK				0x0000ffff
#define OEM_ID_SHFT				0
#define MODEL_ID_OFFSET				0x0804
#define MODEL_ID_BMSK				0x0000ffff
#define MODEL_ID_SHFT				0
#define JTAG_ID_OFFSET				0x0844
#define JTAG_ID_AUTH_BMSK			0x0fffffff
#define JTAG_ID_AUTH_SHFT			0
#define SERIAL_NUM_OFFSET			0x0710

#define TCSR_SOC_HW_VERSION_ADDR		0x01FC8000
#define SOC_HW_VERSION_FAM_DEV_BMSK		0xffff0000
#define SOC_HW_VERSION_FAM_DEV_SHFT		16

#define OEM_CONFIG2_OFFSET			0x0308
#define EKU_ENFORCEMENT_EN_SHFT			30

#endif /* __QFPROM_TARGET_H__ */
