/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef __KERNEL_VECTOR_H
#define __KERNEL_VECTOR_H

#include <compiler.h>
#include <types_ext.h>

#define VECTOR_NUM_REGS		U(32)

/*
 * The vector register file plus the vector CSRs. The register area is sized
 * at runtime from vlenb, so the whole struct is heap allocated rather than
 * embedded, unlike struct vfp_state.
 */
struct vector_regs {
	unsigned long vstart;
	unsigned long vtype;
	unsigned long vl;
	unsigned long vcsr;
	uint8_t vregs[];
};

struct vector_state {
	/* Allocated by the thread layer, sized by vector_regs_size() */
	struct vector_regs *regs;
	/* xstatus.VS at the time of vector_lazy_save_state_init() */
	unsigned long vs;
};

/* Header plus VECTOR_NUM_REGS * vlenb, the size to allocate for a context */
size_t vector_regs_size(void);

#ifdef CFG_RISCV_WITH_VECTOR
/*
 * vector_is_enabled() - Returns true if the vector unit is enabled
 */
bool vector_is_enabled(void);

/*
 * vector_enable() - Enables the vector unit by taking xstatus.VS out of Off
 */
void vector_enable(void);

/*
 * vector_disable() - Disables the vector unit by setting xstatus.VS to Off
 */
void vector_disable(void);
#else
static inline bool vector_is_enabled(void)
{
	return false;
}

static inline void vector_enable(void)
{
}

static inline void vector_disable(void)
{
}
#endif

/*
 * vector_lazy_save_state_init() - Saves VS and disables the vector unit
 * @state:	vector state to initialise
 *
 * The registers themselves are left in place, to be saved by
 * vector_lazy_save_state_final() if they turn out to be needed.
 */
void vector_lazy_save_state_init(struct vector_state *state);

/*
 * vector_lazy_save_state_final() - Saves the vector registers
 * @state:	vector state to save to, its regs must be allocated
 * @force_save:	Forces the save even if the unit was disabled at
 *		vector_lazy_save_state_init()
 */
void vector_lazy_save_state_final(struct vector_state *state, bool force_save);

/*
 * vector_lazy_restore_state() - Restores vector state
 * @state:	vector state to restore
 * @full_state:	If the registers should be restored too, false if they were
 *		never touched and only VS has to be put back
 */
void vector_lazy_restore_state(struct vector_state *state, bool full_state);

#endif /*__KERNEL_VECTOR_H*/
