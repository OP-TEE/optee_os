/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef VECTOR_PRIVATE
#define VECTOR_PRIVATE

#include <kernel/vector.h>

/* The unit must be enabled by the caller for the two routines below. */
void vector_save_regs(struct vector_regs *regs);
void vector_restore_regs(struct vector_regs *regs);

#endif /*VECTOR_PRIVATE*/
