/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022, 2025-2026 NXP
 */

#ifndef __KERNEL_MISC_ARCH_H
#define __KERNEL_MISC_ARCH_H

#include <stddef.h>
#include <stdint.h>

/* Bootable hart ID table and its number of valid entries */
extern uint32_t hartids[CFG_TEE_CORE_NB_CORE];
extern size_t hartids_count;

#endif /*__KERNEL_MISC_ARCH_H*/
