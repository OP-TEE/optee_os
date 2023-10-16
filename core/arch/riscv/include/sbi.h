/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __SBI_H
#define __SBI_H

#if defined(CFG_RISCV_SBI)

/* SBI return error codes */
#define SBI_SUCCESS			 0
#define SBI_ERR_FAILURE			-1
#define SBI_ERR_NOT_SUPPORTED		-2
#define SBI_ERR_INVALID_PARAM		-3
#define SBI_ERR_DENIED			-4
#define SBI_ERR_INVALID_ADDRESS		-5
#define SBI_ERR_ALREADY_AVAILABLE	-6
#define SBI_ERR_ALREADY_STARTED		-7
#define SBI_ERR_ALREADY_STOPPED		-8

/* SBI Extension IDs */
#define SBI_EXT_0_1_CONSOLE_PUTCHAR	0x01, 0
#define SBI_EXT_HSM			0x48534D
#define SBI_EXT_TEE			0x544545

/* SBI function IDs for HSM extension */
#define SBI_EXT_HSM_HART_START		U(0)
#define SBI_EXT_HSM_HART_STOP		U(1)
#define SBI_EXT_HSM_HART_GET_STATUS	U(2)
#define SBI_EXT_HSM_HART_SUSPEND	U(3)

#ifndef __ASSEMBLER__

#include <compiler.h>
#include <encoding.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <types_ext.h>
#include <util.h>

void sbi_console_putchar(int ch);
int sbi_boot_hart(uint32_t hart_id, paddr_t start_addr, unsigned long arg);

#endif /*__ASSEMBLER__*/
#endif /*defined(CFG_RISCV_SBI)*/
#endif /*__SBI_H*/
