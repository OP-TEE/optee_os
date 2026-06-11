/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GCC_BASE			UL(0x110000)
#define GCC_SIZE			UL(0x100000)

#define AOP_CMD_DB_BASE			UL(0x90860000)
#define AOP_CMD_DB_SIZE			UL(0x00020000)

#define CFG_SEC_ELF_DDR_ADDR		UL(0x908FF000)
#define CFG_SEC_ELF_DDR_SIZE		UL(0x1000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x380000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x800000000)

#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xd1900000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01c00000)

#define GENI_UART_REG_BASE		UL(0xa8c000)

/* IMEM and Diagnostic buffer */
#define IMEM_BASE			UL(0x14680000)
#define IMEM_SIZE			UL(0x32000)

#endif /* TARGET_CONFIG_H */
