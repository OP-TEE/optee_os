/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_CRYPTO_STM32_COMMON_H
#define __DRIVERS_CRYPTO_STM32_COMMON_H

#include <tee_api_types.h>

enum stm32_cipher_ip_id {
	CRYP_IP,
	SAES_IP,
};

/*
 * Crypto algorithm common macro used in stm32_saes and stm32_cryp driver
 */

#define INT8_BIT			U(8)
#define AES_BLOCK_SIZE_BIT		U(128)
#define AES_BLOCK_SIZE			(AES_BLOCK_SIZE_BIT / INT8_BIT)
#define AES_BLOCK_NB_U32		(AES_BLOCK_SIZE / sizeof(uint32_t))
#define DES_BLOCK_SIZE_BIT		U(64)
#define DES_BLOCK_SIZE			(DES_BLOCK_SIZE_BIT / INT8_BIT)
#define DES_BLOCK_NB_U32		(DES_BLOCK_SIZE / sizeof(uint32_t))
#define MAX_BLOCK_SIZE_BIT		AES_BLOCK_SIZE_BIT
#define MAX_BLOCK_SIZE			AES_BLOCK_SIZE
#define MAX_BLOCK_NB_U32		AES_BLOCK_NB_U32
#define AES_KEYSIZE_128			U(16)
#define AES_KEYSIZE_192			U(24)
#define AES_KEYSIZE_256			U(32)
#define AES_IVSIZE			U(16)

TEE_Result stm32_register_authenc(void);
TEE_Result stm32_register_cipher(enum stm32_cipher_ip_id);

#endif /* __DRIVERS_CRYPTO_STM32_COMMON_H */
