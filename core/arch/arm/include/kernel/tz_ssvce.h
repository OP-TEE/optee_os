/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TZ_SSVCE_H
#define TZ_SSVCE_H

#ifndef ASM

#include <types_ext.h>

unsigned int secure_get_cpu_id(void);

void arm_cl1_d_cleanbysetway(void);
void arm_cl1_d_invbysetway(void);
void arm_cl1_d_cleaninvbysetway(void);
/* End address is included in the range (last address in range)*/
void arm_cl1_d_cleanbyva(void *start, void *end);
/* End address is included in the range (last address in range)*/
void arm_cl1_d_invbyva(void *start, void *end);
/* End address is included in the range (last address in range)*/
void arm_cl1_d_cleaninvbyva(void *start, void *end);
void arm_cl1_i_inv_all(void);
/* End address is included in the range (last address in range)*/
void arm_cl1_i_inv(void *start, void *end);

void secure_mmu_datatlbinvall(void);
void secure_mmu_unifiedtlbinvall(void);
void secure_mmu_unifiedtlbinvbymva(unsigned long addr);
void secure_mmu_unifiedtlbinv_curasid(void);
void secure_mmu_unifiedtlbinv_byasid(unsigned long asid);

void secure_mmu_disable(void);
#endif /*!ASM*/

#ifdef ARM64
/* D$ set/way op type defines */
#define DCISW			0x0
#define DCCISW			0x1
#define DCCSW			0x2

#ifndef ASM
void flush_dcache_range(vaddr_t va, size_t len);
void inv_dcache_range(vaddr_t va, size_t len);
void dcsw_op_louis(uint32_t op);
void dcsw_op_all(uint32_t op);
#endif /*!ASM*/
#endif /*ARM64*/

#endif
