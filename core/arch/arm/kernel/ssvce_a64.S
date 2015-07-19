/*
 * Copyright (c) 2015, Linaro Limited
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
#include <kernel/tz_ssvce.h>
#include <arm64.h>
#include <asm.S>

/* void secure_mmu_unifiedtlbinvall(void); */
FUNC secure_mmu_unifiedtlbinvall , :
	tlbi	vmalle1
	isb
	ret
END_FUNC secure_mmu_unifiedtlbinvall

/* void secure_mmu_unifiedtlbinv_curasid(void) */
FUNC secure_mmu_unifiedtlbinv_curasid , :
	mrs	x0, ttbr0_el1
	lsr	x0, x0, #TTBR_ASID_SHIFT
	b	secure_mmu_unifiedtlbinv_byasid
END_FUNC secure_mmu_unifiedtlbinv_curasid

/* void secure_mmu_unifiedtlbinv_byasid(unsigned int asid); */
FUNC secure_mmu_unifiedtlbinv_byasid , :
	and	x0, x0, #TTBR_ASID_MASK
	tlbi	aside1, x0
	isb
	ret
END_FUNC secure_mmu_unifiedtlbinv_byasid

/*
 * Compatibility wrappers to be used while the rest of the code stops caring
 * about which cache level it operates on. CL1 -> Inner cache.
 */

/* void arm_cl1_d_cleanbysetway(void); */
FUNC arm_cl1_d_cleanbysetway , :
	mov	x0, #DCCSW
	b	dcsw_op_all
END_FUNC arm_cl1_d_cleanbysetway

/* void arm_cl1_d_invbysetway(void); */
FUNC arm_cl1_d_invbysetway , :
	mov	x0, #DCISW
	b	dcsw_op_all
END_FUNC arm_cl1_d_invbysetway

/* void arm_cl1_d_cleaninvbysetway(void); */
FUNC arm_cl1_d_cleaninvbysetway , :
	mov	x0, #DCCISW
	b	dcsw_op_all
END_FUNC arm_cl1_d_cleaninvbysetway

/* void arm_cl1_d_cleanbyva(void *s, void *e); */
FUNC arm_cl1_d_cleanbyva , :
	sub	x1, x1, x0
	add	x1, x1, #1
	/*
	 * flush_dcache_range() does Clean+Invalidate, but that shouldn't
	 * matter to the caller.
	 */
	b	flush_dcache_range
END_FUNC arm_cl1_d_cleanbyva

/* void arm_cl1_d_invbyva(void *s, void *e); */
FUNC arm_cl1_d_invbyva , :
	sub	x1, x1, x0
	add	x1, x1, #1
	b	inv_dcache_range
END_FUNC arm_cl1_d_invbyva

/* void arm_cl1_d_cleaninvbyva(void *s, void *e); */
FUNC arm_cl1_d_cleaninvbyva , :
	sub	x1, x1, x0
	add	x1, x1, #1
	b	flush_dcache_range
END_FUNC arm_cl1_d_cleaninvbyva

/* void arm_cl1_i_inv_all( void ); */
FUNC arm_cl1_i_inv_all , :
	ic	ialluis
	isb
	ret
END_FUNC arm_cl1_i_inv_all

/* void arm_cl1_i_inv(void *start, void *end); */
FUNC arm_cl1_i_inv , :
	/*
	 * Invalidate the entire icache instead, it shouldn't matter to the
	 * caller.
	 */
	b	arm_cl1_i_inv_all
END_FUNC arm_cl1_i_inv
