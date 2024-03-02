/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_DELAY_ARCH_H
#define __KERNEL_DELAY_ARCH_H

#include <riscv.h>
#include <stdint.h>

static inline unsigned int delay_cnt_freq(void)
{
	return read_cntfrq();
}

static inline uint64_t delay_cnt_read(void)
{
	return read_time();
}
#endif /*__KERNEL_DELAY_ARCH_H*/
