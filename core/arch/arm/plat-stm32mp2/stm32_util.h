/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <drivers/stm32mp2_rcc_util.h>
#include <kernel/spinlock.h>
#include <stdint.h>
#include <types_ext.h>

#define may_spin_lock(lock)		  cpu_spin_lock_xsave(lock)
#define may_spin_unlock(lock, exceptions) cpu_spin_unlock_xrestore(lock, \
								   exceptions)

bool stm32mp_allow_probe_shared_device(const void *fdt, int node);

#endif /*__STM32_UTIL_H__*/
