/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */

#ifndef __KERNEL_ABORT_H
#define __KERNEL_ABORT_H

#define ABORT_TYPE_UNDEF		0
#define ABORT_TYPE_PREFETCH		1
#define ABORT_TYPE_DATA			2
/* Dump stack on user mode panic (not an abort) */
#define ABORT_TYPE_USER_MODE_PANIC	3
#define ABORT_TYPE_ILLEGAL_INST		4

/* Opcode for Illegal inst */
/* Standard Floating-Point Extension (F/D/Q) Major Opcodes */
#define OPCODE_FL_LOAD            0x07    /* Floating-Point Load (flw, fld, flq) */
#define OPCODE_FS_STORE           0x27    /* Floating-Point Store (fsw, fsd, fsq) */
#define OPCODE_FMADD              0x43    /* Fused Multiply-Add */
#define OPCODE_FMSUB              0x47    /* Fused Multiply-Subtract */
#define OPCODE_FNMSUB             0x4B    /* Fused Negative Multiply-Subtract */
#define OPCODE_FNMADD             0x4F    /* Fused Negative Multiply-Add */
#define OPCODE_FP_ARITH           0x53    /* General Floating-Point Arithmetic (fadd, fsub, etc.) */

/* Standard Vector Extension (V) Major Opcodes */
#define OPCODE_V_LOAD             0x07    /* Vector Load Configuration (vle8, vle32, vl8r) */
#define OPCODE_V_STORE            0x27    /* Vector Store Configuration (vse8, vse32, vs8r) */
#define OPCODE_V_ARITH            0x57    /* Vector Arithmetic & Configurations (OP-V Space) */

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <types_ext.h>

struct abort_info {
	uint32_t abort_type;
	uint32_t fault_descr;	/* only valid for data of prefetch abort */
	vaddr_t va;
	uint32_t pc;
	struct thread_abort_regs *regs;
};

/* Print abort info to the console */
void abort_print(struct abort_info *ai);

/* Print abort info + stack dump to the console */
void abort_print_error(struct abort_info *ai);

void abort_handler(uint32_t abort_type, struct thread_abort_regs *regs);

/*
 * Platform specific handler for external abort exceptions.
 * CFG_EXTERNAL_ABORT_PLAT_HANDLER must be enabled to have the platform handler
 * be called.
 */
void plat_external_abort_handler(struct abort_info *ai);

bool abort_is_user_exception(struct abort_info *ai);

bool abort_is_write_fault(struct abort_info *ai);

/* Called from a normal thread */
void abort_print_current_ts(void);

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_ABORT_H*/

