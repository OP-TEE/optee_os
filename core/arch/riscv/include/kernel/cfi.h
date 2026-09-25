/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __KERNEL_CFI_H
#define __KERNEL_CFI_H

#include <stdbool.h>

/*
 * Control-flow integrity for user mode: Zicfilp landing pads
 * (CFG_TA_ZICFILP) and Zicfiss shadow stacks (CFG_TA_ZICFISS).
 */
#if defined(CFG_TA_ZICFILP) || defined(CFG_TA_ZICFISS)
/* Probe and enable the extensions on the calling hart, once at boot */
void cfi_init_hart(void);
#else
static inline void cfi_init_hart(void) { }
#endif

#endif /*__KERNEL_CFI_H*/
