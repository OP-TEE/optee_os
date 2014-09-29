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
#ifndef TEE_MMU_UNPG_H
#define TEE_MMU_UNPG_H

#include <stdint.h>

struct tee_mmu_mapping {
	uint32_t ttbr0;
	uint32_t ctxid;
};

void tee_mmu_get_map(struct tee_mmu_mapping *map);

void tee_mmu_set_map(struct tee_mmu_mapping *map);

/*
 * Switch TTBR0 configuration and Context ID (PROCID & ASID)
 */
void tee_mmu_switch(uint32_t ttbr0_base, uint32_t ctxid);

/*
 * Invalidate TLB entries given a asid
 */
void tee_mmu_invtlb_asid(uint32_t asid);

/*
 * Invalidate TLB entries
 */
void invalidate_mmu_tlb(void);

/*
 * Virtual to Physical address translation
 */
uint32_t translate_va2pa(uint32_t va);

#endif /* TEE_MMU_UNPG_H */
