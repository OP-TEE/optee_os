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

#include <mm/tee_pager_defines.h>
#include <kernel/tz_ssvce_def.h>

.global TEE_PAGER_INIT_asm
.global TEE_PAGER_VECT_TABLE
.global TEE_PAGER_GET_IFAR_asm
.global TEE_PAGER_GET_DFAR_asm
.global TEE_PAGER_GET_DFSR_asm
.global TEE_PAGER_GET_IFSR_asm
.global TEE_PAGER_GET_CPUID_asm
.global tee_pager_get_spsr
.global TEE_PAGER_RES_asm


.set TEE_PAGER_reset_addr,          0xffff0000
.set TEE_PAGER_res_addr,            0xffff0014
.set TEE_PAGER_fiq_addr,            0xffff001c

.section .text
.balign 4
.code 32

.func TEE_PAGER_GET_CPUID_asm
TEE_PAGER_GET_CPUID_asm:
        mrc p15,0,r0,c0,c0,5    @ Read Multiprocessor Affinity Register
        bx      lr
.endfunc

.func TEE_PAGER_GET_IFAR_asm
TEE_PAGER_GET_IFAR_asm:
        mrc     p15, 0, r0, c6, c0, 2
        bx      lr
.endfunc

.func TEE_PAGER_GET_DFAR_asm
TEE_PAGER_GET_DFAR_asm:
        mrc     p15, 0, r0, c6, c0, 0
        bx      lr
.endfunc

.func TEE_PAGER_GET_DFSR_asm
TEE_PAGER_GET_DFSR_asm:
        mrc     p15, 0, r0, c5, c0, 0
        bx      lr
.endfunc

.func TEE_PAGER_GET_IFSR_asm
TEE_PAGER_GET_IFSR_asm:
        mrc     p15, 0, r0, c5, c0, 1
        bx      lr
.endfunc

/* uint32_t tee_pager_get_spsr(void); */
.func tee_pager_get_spsr
tee_pager_get_spsr:
        mrs     r0, spsr
        bx      lr
.endfunc

.func TEE_PAGER_INIT_asm
TEE_PAGER_INIT_asm:
        push    {r4, lr}

        @ Update configuration of TTBR0
        mrc     p15, 0, r4, c2, c0, 0
        mcr     p15, 0, r4, c2, c0, 0

        @ Change to TTBR1
        mcr     p15, 0, r4, c2, c0, 1
        mrc     p15, 0, r4, c2, c0, 2
        orr     r4, r4, #7
        mcr     p15, 0, r4, c2, c0, 2

        pop     {r4, pc}

.endfunc

