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
#define SBI_EXT_0_1_CONSOLE_PUTCHAR	0x01
#define SBI_EXT_BASE			0x10
#define SBI_EXT_HSM			0x48534D
#define SBI_EXT_DBCN			0x4442434E
#define SBI_EXT_TEE			0x544545

#ifndef __ASSEMBLER__

/* SBI function IDs for Base extension */
enum sbi_ext_base_fid {
	SBI_EXT_BASE_GET_SPEC_VERSION = 0,
	SBI_EXT_BASE_GET_IMP_ID,
	SBI_EXT_BASE_GET_IMP_VERSION,
	SBI_EXT_BASE_PROBE_EXT,
	SBI_EXT_BASE_GET_MVENDORID,
	SBI_EXT_BASE_GET_MARCHID,
	SBI_EXT_BASE_GET_MIMPID,
};

/* SBI function IDs for HSM extension */
enum sbi_ext_hsm_fid {
	SBI_EXT_HSM_HART_START = 0,
	SBI_EXT_HSM_HART_STOP,
	SBI_EXT_HSM_HART_GET_STATUS,
	SBI_EXT_HSM_HART_SUSPEND,
};

/* SBI function IDs for Debug Console extension */
enum sbi_ext_dbcn_fid {
	SBI_EXT_DBCN_CONSOLE_WRITE = 0,
	SBI_EXT_DBCN_CONSOLE_READ = 1,
	SBI_EXT_DBCN_CONSOLE_WRITE_BYTE = 2,
};

#include <compiler.h>
#include <encoding.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <types_ext.h>
#include <util.h>

int sbi_probe_extension(int extid);
void sbi_console_putchar(int ch);
int sbi_dbcn_write_byte(unsigned char ch);
int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg);

#endif /*__ASSEMBLER__*/
#endif /*defined(CFG_RISCV_SBI)*/
#endif /*__SBI_H*/
