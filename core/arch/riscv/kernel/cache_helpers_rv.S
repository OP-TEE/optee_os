/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023,2026 NXP
 */

#include <asm.S>
#include <riscv.h>

#ifdef CFG_RISCV_ISA_ZICBOM
/*
 * Apply a Zicbom cache-block operation to every cache block overlapping
 * [a0, a0 + a1). The leading FENCE orders prior memory accesses before
 * the operations, the trailing one orders the operations before
 * subsequent accesses (and device accesses, "fence" being
 * "fence iorw, iorw").
 */
.macro cbo_range op
	fence
	add	a1, a0, a1
	li	t0, -CFG_RISCV_CBOM_BLOCK_SIZE
	and	a0, a0, t0
1:	cbo.\op	(a0)
	addi	a0, a0, CFG_RISCV_CBOM_BLOCK_SIZE
	bltu	a0, a1, 1b
	fence
	ret
.endm

/* void dcache_cleaninv_range(void *addr, size_t size); */
FUNC dcache_cleaninv_range , :
	cbo_range flush
END_FUNC dcache_cleaninv_range

/* void dcache_clean_range(void *addr, size_t size); */
FUNC dcache_clean_range , :
	cbo_range clean
END_FUNC dcache_clean_range

/*
 * void dcache_inv_range(void *addr, size_t size);
 *
 * Executed from S-mode, CBO.INVAL is either an invalidate or a flush
 * depending on menvcfg.CBIE, both of which are acceptable here.
 */
FUNC dcache_inv_range , :
	cbo_range inval
END_FUNC dcache_inv_range
#else
/*
 * Without Zicbom there is no architectural cache-block management. The
 * range operations rely on the FENCE instruction, which orders device I/O
 * and memory accesses as viewed by other RISC-V harts and external devices
 * or coprocessors ("fence" is "fence iorw, iorw"). This is sufficient on
 * cache-coherent platforms only.
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
#endif /* CFG_RISCV_ISA_ZICBOM */

/*
 * void dcache_op_all(unsigned long op_type);
 *
 * RISC-V has no architectural whole-cache maintenance operation, Zicbom
 * being block-based. A platform with non-coherent caches has to provide
 * its own implementation.
 */
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
