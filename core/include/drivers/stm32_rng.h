/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#ifndef __STM32_RNG_H__
#define __STM32_RNG_H__

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

/*
 * As stm32_rng_read() but excluding clocks/reset dependencies.
 *
 * @rng_base: Caller provides the RNG interface base address
 * @out: Output buffer
 * @size: Pointer to input/output byte size of the output buffer
 * Return a TEE_Result compliant sttus
 *
 * When successfully returning, @size stores the number of bytes
 * effectively generated in the output buffer @out. The input value
 * of @size gives the size available in buffer @out.
 */
TEE_Result stm32_rng_read_raw(vaddr_t rng_base, uint8_t *out, size_t *size);

#endif /*__STM32_RNG_H__*/
