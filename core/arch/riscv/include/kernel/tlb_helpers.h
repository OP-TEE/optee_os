/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef TLB_HELPERS_H
#define TLB_HELPERS_H

#ifndef __ASSEMBLER__

void tlbi_all(void);
void tlbi_asid(unsigned long asid);

#endif /*!__ASSEMBLER__*/

#endif /* TLB_HELPERS_H */
