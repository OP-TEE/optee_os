/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __PTA_STM32MP_BSEC_H
#define __PTA_STM32MP_BSEC_H

#define PTA_BSEC_UUID { 0x94cf71ad, 0x80e6, 0x40b5, \
	{ 0xa7, 0xc6, 0x3d, 0xc5, 0x01, 0xeb, 0x28, 0x03 } }

/**
 * Read OTP memory
 *
 * [in]		value[0].a		OTP start offset in byte
 * [in]		value[0].b		Access type, see PTA_BSEC_TYPE_*
 * [out]	memref[1].buffer	Output buffer to store read values
 * [out]	memref[1].size		Size of OTP to be read
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_ACCESS_DENIED - OTP not accessible by caller
 */
#define PTA_BSEC_CMD_READ_OTP		0x0

/**
 * Write OTP memory
 *
 * [in]		value[0].a		OTP start offset in byte
 * [in]		value[0].b		Access type (0 : shadow,
 *					1 : fuse, 2 : lock)
 * [in]		memref[1].buffer	Input buffer to read values
 * [in]		memref[1].size		Size of OTP to be written
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_ACCESS_DENIED - OTP not accessible by caller
 */
#define PTA_BSEC_CMD_WRITE_OTP		0x1

/**
 * Get BSEC state
 * Return the chip security level by reading the BSEC state
 *
 * [out]	value[0].a		One of PTA_BSEC_STATE_*
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_BSEC_CMD_GET_STATE		0x3

enum stm32_bsec_pta_sec_state {
	PTA_BSEC_STATE_SEC_OPEN = 0,
	PTA_BSEC_STATE_SEC_CLOSE = 1,
	PTA_BSEC_STATE_INVALID = 3
};

/*
 * Access types identifiers for PTA_BSEC_CMD_READ_OTP and
 * PTA_BSEC_CMD_WRITE_OTP = value[in].b.
 *
 * PTA_BSEC_SHADOW_ACCESS	Access OTP shadow memory
 * PTA_BSEC_FUSE_ACCESS	Access	OTP fuse memory
 * PTA_BSEC_LOCKS_ACCESS	Access OTP locks. The locks value read/written
 *				in memref[1] 32bit words are related to bit flag
 *				masks PTA_BSEC_LOCK_*.
 */
#define PTA_BSEC_SHADOW_ACCESS		0
#define PTA_BSEC_FUSE_ACCESS		1
#define PTA_BSEC_LOCKS_ACCESS		2

/*
 * PTA_BSEC_LOCK_* - Bit mask of OTP locks in memref[1]
 *
 * PTA_BSEC_LOCK_PERM		Fuse programming permanent lock
 * PTA_BSEC_LOCK_SHADOW_R	Shadow programming (from fuse) lock
 * PTA_BSEC_LOCK_SHADOW_W	Shadow memory write lock
 * PTA_BSEC_LOCK_SHADOW_P	Fuse programming sticky lock
 * PTA_BSEC_LOCK_ERROR		Flag indicating an error in lock access
 */
#define PTA_BSEC_LOCK_PERM			BIT(30)
#define PTA_BSEC_LOCK_SHADOW_R			BIT(29)
#define PTA_BSEC_LOCK_SHADOW_W			BIT(28)
#define PTA_BSEC_LOCK_SHADOW_P			BIT(27)
#define PTA_BSEC_LOCK_ERROR			BIT(26)

#endif /* __PTA_STM32MP_BSEC_H */
