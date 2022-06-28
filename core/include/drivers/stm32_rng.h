/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RNG_H__
#define __DRIVERS_STM32_RNG_H__

#include <stdint.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Fill buffer with bytes from the STM32_RNG
 * @out: Output buffer
 * @size: Byte size of the output buffer
 * Return a TEE_Result compliant sttus
 */
TEE_Result stm32_rng_read(uint8_t *out, size_t size);

#endif /*__DRIVERS_STM32_RNG_H__*/
