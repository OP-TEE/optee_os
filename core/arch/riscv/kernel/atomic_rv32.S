/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Mika Tammi
 */

#include <asm.S>

/*
 * uint64_t __atomic_load_8(const volatile void *ptr, int memorder)
 *
 * RV32 has no 64-bit atomic load, so GCC calls this libatomic routine for
 * __atomic_load_n() on 64-bit objects. The core does that only through
 * READ_ONCE() of fields of messages the normal world writes in shared
 * memory, where the point is reading each value once, not atomicity: each
 * half is read once, with no retry loop that a hostile normal world could
 * keep spinning.
 */
FUNC __atomic_load_8 , :
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	ret
END_FUNC __atomic_load_8
