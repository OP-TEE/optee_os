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

#ifndef SM_SM_H
#define SM_SM_H

#include <types_ext.h>

struct sm_nsec_ctx {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t irq_spsr;
	uint32_t irq_sp;
	uint32_t irq_lr;
	uint32_t fiq_spsr;
	uint32_t fiq_sp;
	uint32_t fiq_lr;
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t abt_spsr;
	uint32_t abt_sp;
	uint32_t abt_lr;
	uint32_t und_spsr;
	uint32_t und_sp;
	uint32_t und_lr;
	uint32_t mon_lr;
	uint32_t mon_spsr;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	/* Only stored on FIQ entry */
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
};

struct sm_sec_ctx {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t irq_spsr;
	uint32_t irq_sp;
	uint32_t irq_lr;
	uint32_t fiq_spsr;
	uint32_t fiq_sp;
	uint32_t fiq_lr;
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t abt_spsr;
	uint32_t abt_sp;
	uint32_t abt_lr;
	uint32_t und_spsr;
	uint32_t und_sp;
	uint32_t und_lr;
	uint32_t mon_lr;
	uint32_t mon_spsr;
	uint32_t entry_reason;
};

/* Returns storage location of non-secure context for current CPU */
struct sm_nsec_ctx *sm_get_nsec_ctx(void);

/* Returns storage location of secure context for current CPU */
struct sm_sec_ctx *sm_get_sec_ctx(void);

/* Returns stack pointer to use in monitor mode for current CPU */
void *sm_get_sp(void);


/*
 * Initializes secure monitor, must be called by each CPU
 */
void sm_init(vaddr_t stack_pointer);

void sm_set_entry_vector(void *entry_vector);

#endif /*SM_SM_H*/
