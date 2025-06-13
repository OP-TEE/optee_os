/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 SiFive, Inc
 */

#ifndef __KERNEL_RISCV_ELF_H__
#define __KERNEL_RISCV_ELF_H__

#define R_RISCV_32		1
#define R_RISCV_64		2
#define R_RISCV_RELATIVE	3

#ifdef RV32
#define RELOC_TYPE		R_RISCV_32
#define SYM_INDEX		0x8
#define SYM_SIZE		0x10
#else
#define RELOC_TYPE		R_RISCV_64
#define SYM_INDEX		0x20
#define SYM_SIZE		0x18
#endif

#endif /*__KERNEL_RISCV_ELF_H__*/
