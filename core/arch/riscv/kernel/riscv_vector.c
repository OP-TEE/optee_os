/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Limited
 */

#include <kernel/riscv_vector.h>
#include <types_ext.h>

void riscv_vector_save_internal(struct riscv_vector_state *dst)
{
	unsigned long vlenb;
	uint8_t *base;

	if (!dst)
		return;

	asm volatile("csrr %0, vtype" : "=r"(dst->vtype));
	asm volatile("csrr %0, vl" : "=r"(dst->vl));
	asm volatile("csrr %0, vcsr" : "=r"(dst->vcsr));
	asm volatile("csrr %0, vstart" : "=r"(dst->vstart));
	asm volatile("csrr %0, 0xc22" : "=r"(vlenb)); /* CSR_VLENB = 0xc22 */

	base = dst->vregs;

#define SAVE_VREG_CHUNK(i)					\
	asm volatile(						\
		"       .option push\n\t"			\
		"       .option arch, +v\n\t"			\
		"       vs8r.v v" #i ", (%0)\n\t"		\
		"       .option pop\n\t"			\
		:: "r"(base + (i) * vlenb) : "memory")

	SAVE_VREG_CHUNK(0);
	SAVE_VREG_CHUNK(8);
	SAVE_VREG_CHUNK(16);
	SAVE_VREG_CHUNK(24);
#undef SAVE_VREG_CHUNK
}

void riscv_vector_restore_internal(const struct riscv_vector_state *src)
{
	unsigned long vlenb;
	const uint8_t *base;

	if (!src)
		return;

	asm volatile("csrw vcsr, %0" :: "r"(src->vcsr));
	asm volatile("csrw vstart, %0" :: "r"(src->vstart));

	/* Re-establish execution parameters prior to block transfer */
	asm volatile(
		"       .option push\n\t"
		"       .option arch, +v\n\t"
		"       vsetvl zero, %0, %1\n\t"
		"       .option pop\n\t"
		:: "r"(src->vl), "r"(src->vtype));

	asm volatile("csrr %0, 0xc22" : "=r"(vlenb));
	base = src->vregs;

#define RESTORE_VREG_CHUNK(i)					\
								\
	asm volatile(						\
		"       .option push\n\t"			\
		"       .option arch, +v\n\t"			\
		"       vl8r.v v" #i ", (%0)\n\t"		\
		"       .option pop\n\t"			\
		:: "r"(base + (i) * vlenb) : "memory")

	RESTORE_VREG_CHUNK(0);
	RESTORE_VREG_CHUNK(8);
	RESTORE_VREG_CHUNK(16);
	RESTORE_VREG_CHUNK(24);
#undef RESTORE_VREG_CHUNK
}

