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

#include <kernel/tz_proc_def.h>

        .global tee_mmu_switch
        .global tee_mmu_set_context
        .global tee_mmu_invtlb_asid
        .global tee_mmu_get_ttbr0
        .global tee_mmu_get_context

        .section .text
        .balign 4
        .code 32

        /*
         * INPUT - r0, ttbr0 base
         *         r1, Context ID
         *
         * Disable IRQ/FIQs during the operation (atomic ASID/TTBR0 loading).
         */
        .func tee_mmu_switch
tee_mmu_switch:

        /* save/mask IRQs/FIQs */
        mrs     r2, cpsr
        and     r3, r2, #CPSR_FIQ_IRQ_MASK
        orr     r2, r2, #CPSR_FIQ_IRQ_MASK
        msr     cpsr_cxsf, r2
        /* set reserved context id */
        dsb                     /* ARM erratum 754322 */
        mov     r2, #0
        mcr     p15, 0, r2, c13, c0, 1
        isb
        /* set ttbr0 */
        mcr     p15, 0, r0, c2, c0, 0
        isb
        /* set context id */
        mcr     p15, 0, r1, c13, c0, 1
        isb
        /* restore irq/fiq mask */
        mrs     r1, cpsr
        bic     r1, r1, #CPSR_FIQ_IRQ_MASK
        orr     r1, r1, r3
        msr     cpsr_cxsf, r1

        bx      lr
        .endfunc

        /*
         * INPUT - r0, Context ID
         */
        .func tee_mmu_set_context
tee_mmu_set_context:
        dsb
        mcr     p15, 0, r0, c13, c0, 1
        isb
        bx      lr
        .endfunc
        
        /*
         * INPUT - r0, ASID to be invalidated
         */
        .func tee_mmu_invtlb_asid
tee_mmu_invtlb_asid:
        mcr     p15, 0, r0, c8, c3, 2
        dsb
        /* No isb due to that we know we will take an exception
         * before we need a clean TLB */
        bx      lr
        .endfunc

        /*
         * OUTPUT - r0, ttbr0 base
         */
        .func tee_mmu_get_ttbr0
tee_mmu_get_ttbr0:
        mrc     p15, 0, r0, c2, c0, 0
        bx      lr
        .endfunc

        /*
         * INPUT - r0, Context ID
         */
        .func tee_mmu_get_context
tee_mmu_get_context:
        mrc     p15, 0, r0, c13, c0, 1
        bx      lr
        .endfunc
