/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x380000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x800000000)

/*
 * The Trusted Apps region of the pIMEM vault in the QCS8300 LE memory map.
 * It ends where the DBI dump region starts, 0xd3300000.
 */
#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xd1900000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01a00000)

#define GENI_UART_REG_BASE		UL(0x99c000)

/* IMEM and Diagnostic buffer */
#define IMEM_BASE			UL(0x14680000)
#define IMEM_SIZE			UL(0x32000)

#endif /* TARGET_CONFIG_H */
