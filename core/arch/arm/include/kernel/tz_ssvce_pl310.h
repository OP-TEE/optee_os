/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_TZ_SSVCE_PL310_H
#define __KERNEL_TZ_SSVCE_PL310_H

#include <util.h>
#include <kernel/tz_ssvce_def.h>
#include <types_ext.h>

vaddr_t pl310_base(void);
vaddr_t pl310_nsbase(void);

/*
 * End address is included in the range (last address in range)
 */
void arm_cl2_cleaninvbyway(vaddr_t pl310_base);
void arm_cl2_invbyway(vaddr_t pl310_base);
void arm_cl2_cleanbyway(vaddr_t pl310_base);
void arm_cl2_cleanbypa(vaddr_t pl310_base, paddr_t start, paddr_t end);
void arm_cl2_invbypa(vaddr_t pl310_base, paddr_t start, paddr_t end);
void arm_cl2_cleaninvbypa(vaddr_t pl310_base, paddr_t start, paddr_t end);

#endif /* __KERNEL_TZ_SSVCE_PL310_H */
