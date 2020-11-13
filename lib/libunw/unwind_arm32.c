// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2015-2019 Linaro Limited
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

#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <unw/unwind.h>
#include <util.h>

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

static bool copy_in(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return true;
}

/* Expand a 31-bit signed value to a 32-bit signed value */
static int32_t expand_prel31(uint32_t prel31)
{
	return prel31 | SHIFT_U32(prel31 & BIT32(30), 1);
}

/*
 * Perform a binary search of the index table to find the function
 * with the largest address that does not exceed addr.
 */
static struct unwind_idx *find_index(uint32_t addr)
{
	vaddr_t idx_start = 0;
	vaddr_t idx_end = 0;
	unsigned int min = 0;
	unsigned int mid = 0;
	unsigned int max = 0;
	struct unwind_idx *start = NULL;
	struct unwind_idx *item = NULL;
	int32_t prel31_addr = 0;
	vaddr_t func_addr = 0;

	if (!find_exidx(addr, &idx_start, &idx_end))
		return NULL;

	start = (struct unwind_idx *)idx_start;

	min = 0;
	max = (idx_end - idx_start) / sizeof(struct unwind_idx);

	while (min != max) {
		mid = min + (max - min + 1) / 2;

		item = &start[mid];

		prel31_addr = expand_prel31(item->offset);
		func_addr = (vaddr_t)&item->offset + prel31_addr;

		if (func_addr <= addr)
			min = mid;
		else
			max = mid - 1;
	}

	return &start[min];
}

/* Reads the next byte from the instruction list */
static bool unwind_exec_read_byte(struct unwind_state_arm32 *state,
				  uint32_t *ret_insn)
{
	uint32_t insn;

	if (!copy_in(&insn, (void *)state->insn, sizeof(insn)))
		return false;

	/* Read the unwind instruction */
	*ret_insn = (insn >> (state->byte * 8)) & 0xff;

	/* Update the location of the next instruction */
	if (state->byte == 0) {
		state->byte = 3;
		state->insn += sizeof(uint32_t);
		state->entries--;
	} else {
		state->byte--;
	}

	return true;
}

static bool pop_vsp(uint32_t *reg, vaddr_t *vsp, vaddr_t stack,
		    size_t stack_size)
{
	if (*vsp < stack)
		return false;
	if (*vsp + sizeof(*reg) > stack + stack_size)
		return false;

	if (!copy_in(reg, (void *)*vsp, sizeof(*reg)))
		return false;
	(*vsp) += sizeof(*reg);
	return true;
}

/* Executes the next instruction on the list */
static bool unwind_exec_insn(struct unwind_state_arm32 *state, vaddr_t stack,
			     size_t stack_size)
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
static bool unwind_tab(struct unwind_state_arm32 *state, vaddr_t stack,
		       size_t stack_size)
{
	uint32_t entry;
	uint32_t insn;

	/* Set PC to a known value */
	state->registers[PC] = 0;

	if (!copy_in(&insn, (void *)state->insn, sizeof(insn))) {
		DMSG("Bad insn addr %p", (void *)state->insn);
		return true;
	}

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

bool unwind_stack_arm32(struct unwind_state_arm32 *state,
			vaddr_t stack, size_t stack_size)
{
	struct unwind_idx *index;
	bool finished;

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
	index = find_index(state->start_pc - 2);
	if (!index)
		return false;

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

void print_stack_arm32(struct unwind_state_arm32 *state,
		       vaddr_t stack, size_t stack_size)
{
	trace_printf_helper_raw(TRACE_ERROR, true, "Call stack:");
	do {
		trace_printf_helper_raw(TRACE_ERROR, true, " 0x%08" PRIx32,
					state->registers[PC]);
	} while (unwind_stack_arm32(state, stack, stack_size));
}
