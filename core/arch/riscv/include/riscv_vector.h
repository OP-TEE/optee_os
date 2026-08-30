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

/*
 * xstatus.VS holds the state of the vector unit and takes the same four
 * values as the FS field does for floating point:
 *
 * Off      the unit is disabled, a vector instruction or an access to a
 *          vector CSR traps as an illegal instruction
 * Initial  enabled, the registers hold their initial value
 * Clean    enabled, the registers match the copy held in memory
 * Dirty    enabled, the registers have been written since they were last
 *          saved
 *
 * The helpers come in two flavours: those taking an xstatus value operate
 * on a saved context, since xstatus is part of the register frame restored
 * on the way back to a trapped context, while riscv_vector_write_vs() and
 * friends act on the live CSR of this hart.
 */

static inline unsigned long riscv_vector_get_vs(unsigned long xstatus)
{
#ifdef RV32
	return get_field_u32(xstatus, CSR_XSTATUS_VS_MASK);
#else
	return get_field_u64(xstatus, CSR_XSTATUS_VS_MASK);
#endif
}

static inline unsigned long riscv_vector_set_vs(unsigned long xstatus,
						unsigned long vs)
{
#ifdef RV32
	return set_field_u32(xstatus, CSR_XSTATUS_VS_MASK, vs);
#else
	return set_field_u64(xstatus, CSR_XSTATUS_VS_MASK, vs);
#endif
}

/* Returns true if @xstatus describes a context with the vector unit on */
static inline bool riscv_vector_state_is_enabled(unsigned long xstatus)
{
	return riscv_vector_get_vs(xstatus) != CSR_XSTATUS_VS_OFF;
}

static inline void riscv_vector_write_vs(unsigned long vs)
{
	write_csr(CSR_XSTATUS,
		  riscv_vector_set_vs(read_csr(CSR_XSTATUS), vs));
}

static inline unsigned long riscv_vector_read_vs(void)
{
	return riscv_vector_get_vs(read_csr(CSR_XSTATUS));
}

static inline void riscv_vector_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_VS_MASK);
}

static inline bool riscv_vector_is_enabled(void)
{
	return riscv_vector_read_vs() != CSR_XSTATUS_VS_OFF;
}

/*
 * vlenb is only readable with the unit enabled, so this leaves xstatus.VS
 * as it found it the same way the save and restore routines do.
 */
static inline unsigned long riscv_vector_vlenb(void)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);
	unsigned long vlenb = 0;

	riscv_vector_write_vs(CSR_XSTATUS_VS_INITIAL);
	vlenb = read_csr(CSR_VLENB);
	write_csr(CSR_XSTATUS, xstatus);

	return vlenb;
}

#endif /* !__ASSEMBLER__ */
#endif /* __RISCV_VECTOR_H */
