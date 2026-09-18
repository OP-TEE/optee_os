// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <assert.h>
#include <kernel/vector.h>
#include <riscv.h>
#include <string.h>
#include "vector_private.h"

static unsigned long read_vs(void)
{
	return (read_csr(CSR_XSTATUS) & CSR_XSTATUS_VS_MASK) >>
	       CSR_XSTATUS_VS_SHIFT;
}

static void write_vs(unsigned long vs)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS) & ~CSR_XSTATUS_VS_MASK;

	write_csr(CSR_XSTATUS, xstatus | SHIFT_U32(vs, CSR_XSTATUS_VS_SHIFT));
}

bool vector_is_enabled(void)
{
	return read_vs() != CSR_XSTATUS_VS_OFF;
}

void vector_enable(void)
{
	write_vs(CSR_XSTATUS_VS_CLEAN);
}

void vector_disable(void)
{
	write_vs(CSR_XSTATUS_VS_OFF);
}

void vector_lazy_save_state_init(struct vector_state *state)
{
	state->vs = read_vs();
	vector_disable();
}

void vector_lazy_save_state_final(struct vector_state *state, bool force_save)
{
	if (state->vs != CSR_XSTATUS_VS_OFF || force_save) {
		assert(!vector_is_enabled() && state->regs);
		vector_enable();
		vector_save_regs(state->regs);
		vector_disable();
	}
}

void vector_lazy_restore_state(struct vector_state *state, bool full_state)
{
	if (full_state) {
		/*
		 * Only restore the vector registers if they have been touched
		 * as they otherwise are intact.
		 */

		/* VS is restored to what's in state->vs below */
		assert(state->regs);
		vector_enable();
		vector_restore_regs(state->regs);
	}
	write_vs(state->vs);
}
