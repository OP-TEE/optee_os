/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022, 2025 NXP
 */

#ifndef __KERNEL_MISC_ARCH_H
#define __KERNEL_MISC_ARCH_H

#include <stdint.h>

/* Bootable hart ID table */
extern uint32_t hartids[CFG_TEE_CORE_NB_CORE];

#endif /*__KERNEL_MISC_ARCH_H*/
