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

/* Print a message and reset the system */
void __noreturn do_reset(const char *str);

/*
 * Structure and API function for BSEC driver to get some platform data.
 *
 * @base: BSEC interface registers physical base address
 * @upper_start: Base ID for the BSEC upper words in the platform
 * @max_id: Max value for BSEC word ID for the platform
 */
struct stm32_bsec3_static_cfg {
	paddr_t base;
	unsigned int upper_start;
	unsigned int max_id;
};

void stm32mp_get_bsec3_static_cfg(struct stm32_bsec3_static_cfg *cfg);

#endif /*__STM32_UTIL_H__*/
