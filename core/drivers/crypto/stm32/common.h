/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_CRYPTO_STM32_COMMON_H
#define __DRIVERS_CRYPTO_STM32_COMMON_H

#include <tee_api_types.h>

TEE_Result stm32_register_authenc(void);
TEE_Result stm32_register_cipher(void);

#endif /* __DRIVERS_CRYPTO_STM32_COMMON_H */
