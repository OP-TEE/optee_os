/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_MISC_ARCH_H
#define __KERNEL_MISC_ARCH_H

/* Bootable hart ID table */
extern uint32_t hartids[CFG_TEE_CORE_NB_CORE];

size_t get_core_pos_hartid(void);

#endif /*__KERNEL_MISC_ARCH_H*/
