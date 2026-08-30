/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_VECTOR_H
#define __RISCV_VECTOR_H

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <riscv.h>
#include <types_ext.h>

/*
 * The width of a vector register is discovered at run time from vlenb and
 * can be anything from 8 bytes upwards, so a context cannot be sized from
 * the ISA the core was built for. The register file is a flexible array and
 * a context is allocated for the hart it will run on.
 */
#define RISCV_VECTOR_NUM_REGS	32

/*
 * struct riscv_vector_state - vector register context
 * @vstart:	index the next vector instruction would resume from
 * @vtype:	current vector type, read only, put back through vsetvl
 * @vl:		current vector length, likewise
 * @vcsr:	vector rounding mode and saturation flag
 * @vregs:	v0..v31, each vlenb bytes wide and laid out back to back
 *
 * The layout is shared with riscv_vector.S, see the RISCV_VECTOR_*_OFF
 * defines.
 */
struct riscv_vector_state {
	unsigned long vstart;
	unsigned long vtype;
	unsigned long vl;
	unsigned long vcsr;
	uint8_t vregs[];
};

/*
 * Bytes one context occupies on this hart, the header plus 32 * vlenb.
 * Reads vlenb, so it enables the vector unit for the read the same way the
 * save and restore routines do.
 */
size_t riscv_vector_state_size(void);

void riscv_vector_save_state(struct riscv_vector_state *state);
void riscv_vector_restore_state(struct riscv_vector_state *state);

#endif /* !__ASSEMBLER__ */
#endif /* __RISCV_VECTOR_H */
