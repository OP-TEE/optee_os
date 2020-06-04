// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2015 Linaro Limited
 * Copyright 2013-2014 Andrew Turner.
 * Copyright 2013-2014 Ian Lepore.
 * Copyright 2013-2014 Rui Paulo.
 * Copyright 2013 Eitan Adler.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arm.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/tee_misc.h>
#include <kernel/unwind.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <util.h>

#include "unwind_private.h"

/* The register names */
#define	FP	11
#define	SP	13
#define	LR	14
#define	PC	15

/*
 * Definitions for the instruction interpreter.
 *
 * The ARM EABI specifies how to perform the frame unwinding in the
 * Exception Handling ABI for the ARM Architecture document. To perform
 * the unwind we need to know the initial frame pointer, stack pointer,
 * link register and program counter. We then find the entry within the
 * index table that points to the function the program counter is within.
 * This gives us either a list of three instructions to process, a 31-bit
 * relative offset to a table of instructions, or a value telling us
 * we can't unwind any further.
 *
 * When we have the instructions to process we need to decode them
 * following table 4 in section 9.3. This describes a collection of bit
 * patterns to encode that steps to take to update the stack pointer and
 * link register to the correct values at the start of the function.
 */

/* A special case when we are unable to unwind past this function */
#define	EXIDX_CANTUNWIND	1

/*
 * Entry types.
 * These are the only entry types that have been seen in the kernel.
 */
#define	ENTRY_MASK	0xff000000
#define	ENTRY_ARM_SU16	0x80000000
#define	ENTRY_ARM_LU16	0x81000000

/* Instruction masks. */
#define	INSN_VSP_MASK		0xc0
#define	INSN_VSP_SIZE_MASK	0x3f
#define	INSN_STD_MASK		0xf0
#define	INSN_STD_DATA_MASK	0x0f
#define	INSN_POP_TYPE_MASK	0x08
#define	INSN_POP_COUNT_MASK	0x07
#define	INSN_VSP_LARGE_INC_MASK	0xff

/* Instruction definitions */
#define	INSN_VSP_INC		0x00
#define	INSN_VSP_DEC		0x40
#define	INSN_POP_MASKED		0x80
#define	INSN_VSP_REG		0x90
#define	INSN_POP_COUNT		0xa0
#define	INSN_FINISH		0xb0
#define	INSN_POP_REGS		0xb1
#define	INSN_VSP_LARGE_INC	0xb2

/* An item in the exception index table */
struct unwind_idx {
	uint32_t offset;
	uint32_t insn;
};

/* Expand a 31-bit signed value to a 32-bit signed value */
static int32_t expand_prel31(uint32_t prel31)
{
	return prel31 | SHIFT_U32(prel31 & BIT32(30), 1);
}

/*
 * Perform a binary search of the index table to find the function
 * with the largest address that doesn't exceed addr.
 */
static struct unwind_idx *find_index(uint32_t addr, vaddr_t exidx,
				     size_t exidx_sz)
{
	vaddr_t idx_start, idx_end;
	unsigned int min, mid, max;
	struct unwind_idx *start;
	struct unwind_idx *item;
	int32_t prel31_addr;
	vaddr_t func_addr;

	start = (struct unwind_idx *)exidx;
	idx_start = exidx;
	idx_end = exidx + exidx_sz;

	min = 0;
	max = (idx_end - idx_start) / sizeof(struct unwind_idx);

	while (min != max) {
		mid = min + (max - min + 1) / 2;

		item = &start[mid];

		prel31_addr = expand_prel31(item->offset);
		func_addr = (vaddr_t)&item->offset + prel31_addr;

		if (func_addr <= addr) {
			min = mid;
		} else {
			max = mid - 1;
		}
	}

	return &start[min];
}

/* Reads the next byte from the instruction list */
static bool unwind_exec_read_byte(struct unwind_state_arm32 *state,
				  uint32_t *ret_insn)
{
	uint32_t insn;

	memcpy(&insn, (void *)state->insn, sizeof(insn));

	/* Read the unwind instruction */
	*ret_insn = (insn >> (state->byte * 8)) & 0xff;

	/* Update the location of the next instruction */
	if (state->byte == 0) {
		state->byte = 3;
		state->insn += sizeof(uint32_t);
		state->entries--;
	} else
		state->byte--;

	return true;
}

static bool pop_vsp(uint32_t *reg, vaddr_t *vsp,
		    vaddr_t stack, size_t stack_size)
{
	if (!core_is_buffer_inside(*vsp, sizeof(*reg), stack, stack_size))
		return false;

	memcpy(reg, (void *)*vsp, sizeof(*reg));
	(*vsp) += sizeof(*reg);
	return true;
}

/* Executes the next instruction on the list */
static bool unwind_exec_insn(struct unwind_state_arm32 *state,
			     vaddr_t stack, size_t stack_size)
{
	uint32_t insn;
	vaddr_t vsp = state->registers[SP];
	int update_vsp = 0;

	/* Read the next instruction */
	if (!unwind_exec_read_byte(state, &insn))
		return false;

	if ((insn & INSN_VSP_MASK) == INSN_VSP_INC) {
		state->registers[SP] += ((insn & INSN_VSP_SIZE_MASK) << 2) + 4;

	} else if ((insn & INSN_VSP_MASK) == INSN_VSP_DEC) {
		state->registers[SP] -= ((insn & INSN_VSP_SIZE_MASK) << 2) + 4;

	} else if ((insn & INSN_STD_MASK) == INSN_POP_MASKED) {
		uint32_t mask;
		unsigned int reg;

		/* Load the mask */
		if (!unwind_exec_read_byte(state, &mask))
			return false;
		mask |= (insn & INSN_STD_DATA_MASK) << 8;

		/* We have a refuse to unwind instruction */
		if (mask == 0)
			return false;

		/* Update SP */
		update_vsp = 1;

		/* Load the registers */
		for (reg = 4; mask && reg < 16; mask >>= 1, reg++) {
			if (mask & 1) {
				if (!pop_vsp(&state->registers[reg], &vsp,
					     stack, stack_size))
					return false;
				state->update_mask |= 1 << reg;

				/* If we have updated SP kep its value */
				if (reg == SP)
					update_vsp = 0;
			}
		}

	} else if ((insn & INSN_STD_MASK) == INSN_VSP_REG &&
	    ((insn & INSN_STD_DATA_MASK) != 13) &&
	    ((insn & INSN_STD_DATA_MASK) != 15)) {
		/* sp = register */
		state->registers[SP] =
		    state->registers[insn & INSN_STD_DATA_MASK];

	} else if ((insn & INSN_STD_MASK) == INSN_POP_COUNT) {
		unsigned int count, reg;

		/* Read how many registers to load */
		count = insn & INSN_POP_COUNT_MASK;

		/* Update sp */
		update_vsp = 1;

		/* Pop the registers */
		for (reg = 4; reg <= 4 + count; reg++) {
			if (!pop_vsp(&state->registers[reg], &vsp,
				     stack, stack_size))
				return false;
			state->update_mask |= 1 << reg;
		}

		/* Check if we are in the pop r14 version */
		if ((insn & INSN_POP_TYPE_MASK) != 0) {
			if (!pop_vsp(&state->registers[14], &vsp,
				     stack, stack_size))
				return false;
		}

	} else if (insn == INSN_FINISH) {
		/* Stop processing */
		state->entries = 0;

	} else if (insn == INSN_POP_REGS) {
		uint32_t mask;
		unsigned int reg;

		if (!unwind_exec_read_byte(state, &mask))
			return false;
		if (mask == 0 || (mask & 0xf0) != 0)
			return false;

		/* Update SP */
		update_vsp = 1;

		/* Load the registers */
		for (reg = 0; mask && reg < 4; mask >>= 1, reg++) {
			if (mask & 1) {
				if (!pop_vsp(&state->registers[reg], &vsp,
					     stack, stack_size))
					return false;
				state->update_mask |= 1 << reg;
			}
		}

	} else if ((insn & INSN_VSP_LARGE_INC_MASK) == INSN_VSP_LARGE_INC) {
		uint32_t uleb128;

		/* Read the increment value */
		if (!unwind_exec_read_byte(state, &uleb128))
			return false;

		state->registers[SP] += 0x204 + (uleb128 << 2);

	} else {
		/* We hit a new instruction that needs to be implemented */
		DMSG("Unhandled instruction %.2x", insn);
		return false;
	}

	if (update_vsp)
		state->registers[SP] = vsp;

	return true;
}

/* Performs the unwind of a function */
static bool unwind_tab(struct unwind_state_arm32 *state,
		       vaddr_t stack, size_t stack_size)
{
	uint32_t entry;
	uint32_t insn;

	/* Set PC to a known value */
	state->registers[PC] = 0;

	memcpy(&insn, (void *)state->insn, sizeof(insn));

	/* Read the personality */
	entry = insn & ENTRY_MASK;

	if (entry == ENTRY_ARM_SU16) {
		state->byte = 2;
		state->entries = 1;
	} else if (entry == ENTRY_ARM_LU16) {
		state->byte = 1;
		state->entries = ((insn >> 16) & 0xFF) + 1;
	} else {
		DMSG("Unknown entry: %x", entry);
		return true;
	}

	while (state->entries > 0) {
		if (!unwind_exec_insn(state, stack, stack_size))
			return true;
	}

	/*
	 * The program counter was not updated, load it from the link register.
	 */
	if (state->registers[PC] == 0) {
		state->registers[PC] = state->registers[LR];

		/*
		 * If the program counter changed, flag it in the update mask.
		 */
		if (state->start_pc != state->registers[PC])
			state->update_mask |= 1 << PC;
	}

	return false;
}

bool unwind_stack_arm32(struct unwind_state_arm32 *state, vaddr_t exidx,
			size_t exidx_sz, vaddr_t stack, size_t stack_size)
{
	struct unwind_idx *index;
	bool finished;

	if (!exidx_sz)
		return false;

	/* Reset the mask of updated registers */
	state->update_mask = 0;

	/* The pc value is correct and will be overwritten, save it */
	state->start_pc = state->registers[PC];

	/*
	 * Find the item to run. Subtract 2 from PC to make sure that we're
	 * still inside the calling function in case a __no_return function
	 * (typically panic()) is called unconditionally and may cause LR and
	 * thus this PC to point into the next and entirely unrelated function.
	 */
	index = find_index(state->start_pc - 2, exidx, exidx_sz);

	finished = false;
	if (index->insn != EXIDX_CANTUNWIND) {
		if (index->insn & (1U << 31)) {
			/* The data is within the instruction */
			state->insn = (vaddr_t)&index->insn;
		} else {
			/* A prel31 offset to the unwind table */
			state->insn = (vaddr_t)&index->insn +
				      expand_prel31(index->insn);
		}

		/* Run the unwind function */
		finished = unwind_tab(state, stack, stack_size);
	}

	/* This is the top of the stack, finish */
	if (index->insn == EXIDX_CANTUNWIND)
		finished = true;

	return !finished;
}

static uint32_t offset_prel31(uint32_t addr, int32_t offset)
{
	return (addr + offset) & 0x7FFFFFFFUL;
}

TEE_Result relocate_exidx(void *exidx, size_t exidx_sz, int32_t offset)
{
	size_t num_items = exidx_sz / sizeof(struct unwind_idx);
	struct unwind_idx *start = (struct unwind_idx *)exidx;
	size_t n;

	for (n = 0; n < num_items; n++) {
		struct unwind_idx *item = &start[n];

		if (item->offset & BIT32(31))
			return TEE_ERROR_BAD_FORMAT;

		/* Offset to the start of the function has to be adjusted */
		item->offset = offset_prel31(item->offset, offset);

		if (item->insn == EXIDX_CANTUNWIND)
			continue;
		if (item->insn & BIT32(31)) {
			/* insn is a table entry itself */
			continue;
		}
		/*
		 * insn is an offset to an entry in .ARM.extab so it has to be
		 * adjusted
		 */
		item->insn = offset_prel31(item->insn, offset);
	}
	return TEE_SUCCESS;
}

#if (TRACE_LEVEL > 0)

void print_stack_arm32(int level, struct unwind_state_arm32 *state,
		       vaddr_t exidx, size_t exidx_sz,
		       vaddr_t stack, size_t stack_size)
{
	trace_printf_helper_raw(level, true, "TEE load address @ %#"PRIxVA,
				VCORE_START_VA);
	trace_printf_helper_raw(level, true, "Call stack:");
	do {
		trace_printf_helper_raw(level, true, " 0x%08" PRIx32,
					state->registers[PC]);
	} while (unwind_stack_arm32(state, exidx, exidx_sz, stack, stack_size));
}

#endif

#if defined(ARM32) && (TRACE_LEVEL > 0)

void print_kernel_stack(int level)
{
	struct unwind_state_arm32 state = {};
	uaddr_t exidx = (vaddr_t)__exidx_start;
	size_t exidx_sz = (vaddr_t)__exidx_end - (vaddr_t)__exidx_start;
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;

	/* r7: Thumb-style frame pointer */
	state.registers[7] = read_r7();
	/* r11: ARM-style frame pointer */
	state.registers[FP] = read_fp();
	state.registers[SP] = read_sp();
	state.registers[LR] = read_lr();

	/*
	 * Add 4 to make sure that we have an address well inside this function.
	 * This is needed because we're subtracting 2 from PC when calling
	 * find_index() above. See a comment there for more details.
	 */
	state.registers[PC] = (uint32_t)print_kernel_stack + 4;

	get_stack_hard_limits(&stack_start, &stack_end);
	print_stack_arm32(level, &state, exidx, exidx_sz, stack_start,
			  stack_end - stack_start);
}

#endif

#if defined(ARM32)
vaddr_t *unw_get_kernel_stack(void)
{
	size_t n = 0;
	size_t size = 0;
	size_t exidx_sz = 0;
	vaddr_t *tmp = NULL;
	vaddr_t *addr = NULL;
	struct unwind_state_arm32 state = { };
	uaddr_t exidx = (vaddr_t)__exidx_start;
	vaddr_t stack = thread_stack_start();
	size_t stack_size = thread_stack_size();

	if (SUB_OVERFLOW((vaddr_t)__exidx_end, (vaddr_t)__exidx_start,
			 &exidx_sz))
		return NULL;

	/* r7: Thumb-style frame pointer */
	state.registers[7] = read_r7();
	/* r11: ARM-style frame pointer */
	state.registers[FP] = read_fp();
	state.registers[SP] = read_sp();
	state.registers[LR] = read_lr();

	/*
	 * Add 4 to make sure that we have an address well inside this function.
	 * This is needed because we're subtracting 2 from PC when calling
	 * find_index() above. See a comment there for more details.
	 */
	state.registers[PC] = (uint32_t)unw_get_kernel_stack + 4;

	while (unwind_stack_arm32(&state, exidx, exidx_sz, stack, stack_size)) {
		tmp = unw_grow(addr, &size, (n + 1) * sizeof(vaddr_t));
		if (!tmp)
			goto err;
		addr = tmp;
		addr[n] = state.registers[PC];
		n++;
	}

	if (addr) {
		tmp = unw_grow(addr, &size, (n + 1) * sizeof(vaddr_t));
		if (!tmp)
			goto err;
		addr = tmp;
		addr[n] = 0;
	}

	return addr;
err:
	EMSG("Out of memory");
	free(addr);
	return NULL;
}
#endif
