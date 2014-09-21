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

.section .text
 
.global translate_va2pa
.global invalidate_mmu_tlb

.func translate_va2pa
translate_va2pa:
    // R0 contains the original logical address
    // Use privileged read VA to PA translation priviledges
    MCR p15,0,R0,c7,c8,0
    ISB

    // Read the PAR value
    MRC p15,0,R0,c7,c4,0       
    ISB

    // return to caller
    BX      LR
.endfunc


.func invalidate_mmu_tlb
invalidate_mmu_tlb:
    /* Invalidate entire Unified TLB Inner Sharable. Data R0 value ignored */
    MCR     p15, 0, R0, c8, c3, 0

    
    // Ensure completion of the invalidate TBL operation
    DSB
    
    // Ensure table changes visible to instruction fetch
    ISB
    
    BX      LR
.endfunc

/*-----------------------------------------------------------------------------
    GLOBAL VARIABLES
 *---------------------------------------------------------------------------*/
