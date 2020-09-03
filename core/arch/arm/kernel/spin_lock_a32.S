/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2016, ARM Limited and Contributors. All rights reserved.
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
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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

#include <asm.S>
#include <kernel/spinlock.h>

/* void __cpu_spin_lock(unsigned int *lock) */
FUNC __cpu_spin_lock , :
	mov r2, #SPINLOCK_LOCK
1:
	ldrex r1, [r0]
	cmp r1, #SPINLOCK_UNLOCK
	wfene
	strexeq r1, r2, [r0]
	cmpeq r1, #0
	bne 1b
	dmb
	bx lr
END_FUNC __cpu_spin_lock

/* int __cpu_spin_trylock(unsigned int *lock) - return 0 on success */
FUNC __cpu_spin_trylock , :
	mov r2, #SPINLOCK_LOCK
	mov r1, r0
1:
	ldrex r0, [r1]
	cmp r0, #0
	bne 1f
	strex r0, r2, [r1]
	cmp r0, #0
	bne 1b
	dmb
	bx lr
1:
	clrex
	dmb
	bx lr
END_FUNC __cpu_spin_trylock

/* void __cpu_spin_unlock(unsigned int *lock) */
FUNC __cpu_spin_unlock , :
	dmb
	mov r1, #SPINLOCK_UNLOCK
	str r1, [r0]
	dsb
	sev
	bx lr
END_FUNC __cpu_spin_unlock
