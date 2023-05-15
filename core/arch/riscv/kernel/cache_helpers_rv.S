/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#include <asm.S>
#include <riscv.h>

/*
 * On the below data cache management, we rely on FENCE instruction.
 * The FENCE instruction is used to order device I/O and memory accesses
 * as viewed by other RISC-V harts and external devices or coprocessors.
 * "fence" below is a pseudo-instruction of "fence iorw, iorw" which
 * performs Fence on all memory and I/O.
 */

/* void dcache_cleaninv_range(void *addr, size_t size); */
FUNC dcache_cleaninv_range , :
	fence
	ret
END_FUNC dcache_cleaninv_range

/* void dcache_clean_range(void *addr, size_t size); */
FUNC dcache_clean_range , :
	fence
	ret
END_FUNC dcache_clean_range

/* void dcache_inv_range(void *addr, size_t size); */
FUNC dcache_inv_range , :
	fence
	ret
END_FUNC dcache_inv_range

/* void dcache_op_all(unsigned long op_type); */
FUNC dcache_op_all , :
	fence
	ret
END_FUNC dcache_op_all

/* void icache_inv_all(void); */
FUNC icache_inv_all , :
	/*
	 * FENCE.I instruction provides explicit synchronization
	 * between writes to instruction memory and instruction
	 * fetches on the same hart. This implies instruction cache
	 * management operations as result of executing this instruction.
	 */
	fence.i
	ret
END_FUNC icache_inv_all

/* void icache_inv_range(void *addr, size_t size); */
FUNC icache_inv_range , :
	/*
	 * RISC-V does not have an instruction to flush a range
	 * of the I$, therefore, flush it entirely as invoking
	 * icache_inv_all().
	 */
	fence.i
	ret
END_FUNC icache_inv_range
