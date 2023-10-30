/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <kernel/spinlock.h>
#include <stdint.h>
#include <types_ext.h>

static inline void stm32mp_register_secure_periph_iomem(vaddr_t base __unused)
{
}

static inline void stm32mp_register_non_secure_periph_iomem(vaddr_t base
							    __unused) { }

static inline void stm32mp_register_gpioz_pin_count(size_t count __unused) { }

#define may_spin_lock(lock)		  cpu_spin_lock_xsave(lock)
#define may_spin_unlock(lock, exceptions) cpu_spin_unlock_xrestore(lock, \
								   exceptions)
#endif /*__STM32_UTIL_H__*/
