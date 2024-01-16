/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_TLB_HELPERS_H
#define __KERNEL_TLB_HELPERS_H

#ifndef __ASSEMBLER__

void tlbi_all(void);
void tlbi_va_allasid(vaddr_t va);
void tlbi_asid(unsigned long asid);
void tlbi_va_asid(vaddr_t va, uint32_t asid);

#endif /*!__ASSEMBLER__*/

#endif /* __KERNEL_TLB_HELPERS_H */
