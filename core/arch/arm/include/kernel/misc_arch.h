/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_MISC_ARCH_H
#define __KERNEL_MISC_ARCH_H

#include <arm.h>
#include <kernel/thread.h>
#include <types_ext.h>

size_t get_core_pos_mpidr(uint32_t mpidr);

uint32_t read_mode_sp(int cpu_mode);
uint32_t read_mode_lr(int cpu_mode);

void wait_cycles(unsigned long cycles);

#endif /*__KERNEL_MISC_ARCH_H*/
