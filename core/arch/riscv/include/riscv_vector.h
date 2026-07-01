/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Limited
 */

#ifndef __KERNEL_RISCV_VECTOR_H
#define __KERNEL_RISCV_VECTOR_H

#include <types_ext.h>
#include <compiler.h>

/* CSR Status Bit Masks for Vector Extensions */
#define SSTATUS_VS_MASK       SHIFT_U32(3, 9)   /* bits [10:9] */
#define SSTATUS_VS_OFF        SHIFT_U32(0, 9)
#define SSTATUS_VS_INITIAL    SHIFT_U32(1, 9)
#define SSTATUS_VS_CLEAN      SHIFT_U32(2, 9)
#define SSTATUS_VS_DIRTY      SHIFT_U32(3, 9)

/* Vector Context Struct */
struct riscv_vector_state {
	uint8_t *vregs;
	unsigned long vtype;
	unsigned long vl;
	unsigned long vcsr;
	unsigned long vstart;
};

/* Internal context routers instantiated inside riscv_vector.c */
void riscv_vector_save_internal(struct riscv_vector_state *dst);
void riscv_vector_restore_internal(const struct riscv_vector_state *src);

#endif /* __KERNEL_RISCV_VECTOR_H */
