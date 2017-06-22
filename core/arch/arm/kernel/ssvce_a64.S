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
	/* Ensure visibility of the update to translation table walks */
	dsb	ishst

	tlbi	vmalle1is

	dsb	ish /* Ensure completion of TLB invalidation */
	isb
	ret
END_FUNC secure_mmu_unifiedtlbinvall

/* void secure_mmu_unifiedtlbinv_byasid(unsigned int asid); */
FUNC secure_mmu_unifiedtlbinv_byasid , :
	and	x0, x0, #TTBR_ASID_MASK

	/* Ensure visibility of the update to translation table walks */
	dsb	ishst

	tlbi	aside1is, x0

	dsb	ish /* Ensure completion of TLB invalidation */
	isb
	ret
END_FUNC secure_mmu_unifiedtlbinv_byasid
