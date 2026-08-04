/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __ICE_CONFIG_H
#define __ICE_CONFIG_H

#include <platform_config.h>
#include <stdint.h>

#define ICE_MAX_KEY_IDX				32
#define ICE_CRYPTOCFG_DATA_REGS			16

/* Key sizes in bytes */
#define ICE_AES128_KEY_SIZE			16
#define ICE_AES256_KEY_SIZE			32

/* ICE key register layout within a slot:
 *   n = 0..7  : DATA key (32 bytes, 8 x 4-byte registers)
 *   n = 8..15 : SALT key (32 bytes, 8 x 4-byte registers)
 */
#define ICE_KEY_REG_SIZE			32
#define ICE_KEY_DATA_REG_START			0
#define ICE_KEY_SALT_REG_START			8

/* ICE LUT-keys register definitions, common to eMMC/SDCC and UFS */
#define ICE_CRYPTOCFG_r_n_ADDR(r, n) \
	(ICE_LUT_KEYS + 0x0 + (0x80 * (r)) + (0x4 * (n)))
#define ICE_CRYPTOCFG_r_16_ADDR(r) \
	(ICE_LUT_KEYS + 0x40 + (0x80 * (r)))
#define ICE_CRYPTOCFG_r_16_CFGE_BMSK		0x80000000
#define ICE_CRYPTOCFG_r_16_CFGE_SHFT		31
#define ICE_CRYPTOCFG_r_16_CAPIDX_BMSK		0xff00
#define ICE_CRYPTOCFG_r_16_CAPIDX_SHFT		8
#define ICE_CRYPTOCFG_r_16_DUSIZE_BMSK		0xff
#define ICE_CRYPTOCFG_r_16_DUSIZE_SHFT		0

enum ice_capability_index_type {
	ICE_CIPHER_MODE_XTS_128 = 0x0,
	ICE_CIPHER_MODE_CBC_128 = 0x1,
	ICE_CIPHER_MODE_ECB_128 = 0x2,
	ICE_CIPHER_MODE_XTS_256 = 0x3,
	ICE_CIPHER_MODE_CBC_256 = 0x4,
	ICE_CIPHER_MODE_ECB_256 = 0x5
};

enum ice_data_unit_type {
	ICE_DATA_UNIT_SIZE_512   = 0x1,
	ICE_DATA_UNIT_SIZE_1024  = 0x2,
	ICE_DATA_UNIT_SIZE_2048  = 0x4,
	ICE_DATA_UNIT_SIZE_4096  = 0x8,
	ICE_DATA_UNIT_SIZE_8192  = 0x10,
	ICE_DATA_UNIT_SIZE_16384 = 0x20,
	ICE_DATA_UNIT_SIZE_32768 = 0x40,
	ICE_DATA_UNIT_SIZE_65536 = 0x80
};

#endif /* __ICE_CONFIG_H */
