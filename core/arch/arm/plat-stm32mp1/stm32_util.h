/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018, STMicroelectronics
 */

#ifndef __STM32_UTIL_H__
#define __STM32_UTIL_H__

#include <stdint.h>

/* Backup registers and RAM utils */
uintptr_t stm32mp_bkpreg(unsigned int idx);

/* Platform util for the GIC */
uintptr_t get_gicc_base(void);
uintptr_t get_gicd_base(void);

/* Power management service */
#ifdef CFG_PSCI_ARM32
void stm32mp_register_online_cpu(void);
#else
static inline void stm32mp_register_online_cpu(void)
{
}
#endif

/*
 * Generic spinlock function that bypass spinlock if MMU is disabled or
 * lock is NULL.
 */
uint32_t may_spin_lock(unsigned int *lock);
void may_spin_unlock(unsigned int *lock, uint32_t exceptions);

/*
 * Util for clock gating and to get clock rate for stm32 and platform drivers
 * @id: Target clock ID, ID used in clock DT bindings
 */
void stm32_clock_enable(unsigned long id);
void stm32_clock_disable(unsigned long id);
unsigned long stm32_clock_get_rate(unsigned long id);
bool stm32_clock_is_enabled(unsigned long id);

#endif /*__STM32_UTIL_H__*/
