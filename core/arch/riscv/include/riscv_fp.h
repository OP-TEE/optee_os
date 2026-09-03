/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __RISCV_FP_H
#define __RISCV_FP_H

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <riscv.h>
#include <types_ext.h>

/*
 * struct riscv_fp_state - floating-point register context
 * @fpregs:	f0..f31, each RISCV_FLEN_BITS wide
 * @fcsr:	floating-point control and status register
 *
 * The layout is shared with riscv_fp.S, see RISCV_FP_FCSR_OFF.
 */
struct riscv_fp_state {
#if defined(__riscv_flen) && __riscv_flen == 64
	uint64_t fpregs[32];
#elif defined(__riscv_flen) && __riscv_flen == 32
	uint32_t fpregs[32];
#endif
	uint32_t fcsr;
};

/*
 * riscv_save_fp_state() - save f0..f31 and fcsr into @state
 * riscv_restore_fp_state() - load f0..f31 and fcsr from @state
 *
 * Both enable the floating-point unit for the duration of the transfer and
 * leave xstatus.FS as they found it, so they can be called with the FP unit
 * disabled without disturbing the caller's view of xstatus.
 */
void riscv_save_fp_state(struct riscv_fp_state *state);
void riscv_restore_fp_state(struct riscv_fp_state *state);

/*
 * xstatus.FS holds the state of the FP unit:
 *
 * Off      the FP unit is disabled, an FP instruction traps as an illegal
 *          instruction
 * Initial  enabled, the f registers hold their initial value
 * Clean    enabled, the f registers match the copy held in memory
 * Dirty    enabled, the f registers have been written since they were last
 *          saved
 *
 * The helpers below come in two flavours: those taking an xstatus value
 * operate on a saved context, since xstatus is part of the register frame
 * restored on the way back to a trapped context, while riscv_fp_write_fs()
 * and friends act on the live CSR of this hart.
 */

static inline unsigned long riscv_fp_get_fs(unsigned long xstatus)
{
#ifdef RV32
	return get_field_u32(xstatus, CSR_XSTATUS_FS_MASK);
#else
	return get_field_u64(xstatus, CSR_XSTATUS_FS_MASK);
#endif
}

static inline unsigned long riscv_fp_set_fs(unsigned long xstatus,
					    unsigned long fs)
{
#ifdef RV32
	return set_field_u32(xstatus, CSR_XSTATUS_FS_MASK, fs);
#else
	return set_field_u64(xstatus, CSR_XSTATUS_FS_MASK, fs);
#endif
}

/* Returns true if @xstatus describes a context with the FP unit enabled */
static inline bool riscv_fp_state_is_enabled(unsigned long xstatus)
{
	return riscv_fp_get_fs(xstatus) != CSR_XSTATUS_FS_OFF;
}

static inline void riscv_fp_write_fs(unsigned long fs)
{
	write_csr(CSR_XSTATUS, riscv_fp_set_fs(read_csr(CSR_XSTATUS), fs));
}

static inline unsigned long riscv_fp_read_fs(void)
{
	return riscv_fp_get_fs(read_csr(CSR_XSTATUS));
}

static inline void riscv_fp_disable(void)
{
	clear_csr(CSR_XSTATUS, CSR_XSTATUS_FS_MASK);
}

static inline bool riscv_fp_is_enabled(void)
{
	return riscv_fp_read_fs() != CSR_XSTATUS_FS_OFF;
}

#endif /* !__ASSEMBLER__ */
#endif /* __RISCV_FP_H */
