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

#include <arm32_macros.S>
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
        mrs     r3, cpsr        /* Save CPSR for later use */
        cpsid   if              /* Disable both IRQ and FIQ */

        /* Update the reserved Context ID and TTBR0 in CP15 */
        dsb                     /* ARM erratum 754322 */
        mov     r2, #0
        write_context_id r2     /* Clear the CONTEXTIDR register */

        isb
        write_ttbr0 r0          /* Update TTBR0 with value from function arg. */

        isb
        write_context_id r1     /* Write Context ID from function arg. */

        isb
        msr     cpsr_cxsf, r3   /* Restore the saved CPSR */

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
