/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_NVM_H__
#define __DRIVERS_VERSAL_NVM_H__

#include <drivers/versal_mbox.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define EFUSE_MAX_USER_FUSES 64
#define EFUSE_IV_LEN 12
#define EFUSE_DNA_LEN 16
#define EFUSE_PPK_LEN 32

enum versal_nvm_iv_type {
	EFUSE_META_HEADER_IV_RANGE = 0,
	EFUSE_BLACK_IV,
	EFUSE_PLM_IV_RANGE,
	EFUSE_DATA_PARTITION_IV_RANGE
};

enum versal_nvm_ppk_type {
	EFUSE_PPK0 = 0,
	EFUSE_PPK1,
	EFUSE_PPK2
};

enum versal_nvm_revocation_id {
	EFUSE_REVOCATION_ID_0 = 0,
	EFUSE_REVOCATION_ID_1,
	EFUSE_REVOCATION_ID_2,
	EFUSE_REVOCATION_ID_3,
	EFUSE_REVOCATION_ID_4,
	EFUSE_REVOCATION_ID_5,
	EFUSE_REVOCATION_ID_6,
	EFUSE_REVOCATION_ID_7
};

enum versal_nvm_offchip_id {
	EFUSE_INVLD = -1,
	EFUSE_OFFCHIP_REVOKE_ID_0 = 0,
	EFUSE_OFFCHIP_REVOKE_ID_1,
	EFUSE_OFFCHIP_REVOKE_ID_2,
	EFUSE_OFFCHIP_REVOKE_ID_3,
	EFUSE_OFFCHIP_REVOKE_ID_4,
	EFUSE_OFFCHIP_REVOKE_ID_5,
	EFUSE_OFFCHIP_REVOKE_ID_6,
	EFUSE_OFFCHIP_REVOKE_ID_7
};

#define __aligned_efuse			__aligned(CACHELINE_LEN)

TEE_Result versal_read_efuse_dna(uint32_t *buf, size_t len);
TEE_Result versal_read_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				  size_t num);
TEE_Result versal_read_efuse_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type);
TEE_Result versal_read_efuse_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type);
TEE_Result versal_write_efuse_user(uint32_t *buf, size_t len,
				   uint32_t first, size_t num);

#endif /*__DRIVERS_VERSAL_NVM_H__*/
