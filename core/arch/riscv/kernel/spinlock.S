// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <asm.S>
#include <kernel/spinlock.h>
#include <riscv.h>

/* void __cpu_spin_lock(unsigned int *lock) */
FUNC __cpu_spin_lock , :
	addi	sp, sp, -(RISCV_XLEN_BYTES * 2)
	STR	s0, 0(sp)
	STR	ra, 8(sp)
	mv	s0, a0
1:
	mv	a0, s0
	jal	__cpu_spin_trylock
	addiw	a0, a0, 0
	bnez	a0, 1b
	LDR	ra, 8(sp)
	LDR	s0, 0(sp)
	addi	sp, sp, (RISCV_XLEN_BYTES * 2)
	ret
END_FUNC __cpu_spin_lock


/* void __cpu_spin_unlock(unsigned int *lock)*/
FUNC __cpu_spin_unlock , :
	fence	rw, w
	amoswap.w	x0, x0, 0(a0)
	ret
END_FUNC __cpu_spin_unlock

/* unsigned int __cpu_spin_trylock(unsigned int *lock) */
FUNC __cpu_spin_trylock , :
	li	t0, SPINLOCK_LOCK
	amoswap.w	a0, t0, 0(a0)
	fence	r,rw
	ret
END_FUNC __cpu_spin_trylock

