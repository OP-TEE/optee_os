/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_RISCV_VECTOR_H
#define __KERNEL_RISCV_VECTOR_H

#ifndef __ASSEMBLER__

#include <types_ext.h>
#include <compiler.h>

/* Vector Context Struct */
struct riscv_vector_state {
	unsigned long vcsr;
	unsigned long vstart;
	uint8_t *vregs;
};

/* Internal context routers instantiated inside riscv_vector.c */
void riscv_vector_save(struct riscv_vector_state *dst);
void riscv_vector_restore(const struct riscv_vector_state *src);
size_t riscv_vector_state_size(void);

#endif /* !__ASSEMBLER__ */
#endif /* __KERNEL_RISCV_VECTOR_H */
