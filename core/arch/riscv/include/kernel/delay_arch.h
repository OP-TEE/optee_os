/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_DELAY_ARCH_H
#define __KERNEL_DELAY_ARCH_H

#include <kernel/time.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdint.h>

static inline uint64_t timeout_init_us(uint32_t us)
{
	return read_time() + ((uint64_t)us *
			      CFG_RISCV_MTIME_RATE) / 1000000ULL;
}

static inline bool timeout_elapsed(uint64_t expire)
{
	return read_time() > expire;
}

#endif /*__KERNEL_DELAY_ARCH_H*/
