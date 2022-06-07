/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_SHARED_IO_H__
#define __DRIVERS_STM32_SHARED_IO_H__

#include <stdint.h>
#include <types_ext.h>

/*
 * Shared registers support: common lock for accessing SoC registers
 * shared between several drivers.
 */
void io_clrsetbits32_stm32shregs(vaddr_t va, uint32_t clr, uint32_t set);
void io_mask32_stm32shregs(vaddr_t va, uint32_t value, uint32_t mask);

static inline void io_setbits32_stm32shregs(vaddr_t va, uint32_t value)
{
	io_mask32_stm32shregs(va, value, value);
}

static inline void io_clrbits32_stm32shregs(vaddr_t va, uint32_t value)
{
	io_mask32_stm32shregs(va, 0, value);
}

#endif /* __DRIVERS_STM32_SHARED_IO_H__ */
