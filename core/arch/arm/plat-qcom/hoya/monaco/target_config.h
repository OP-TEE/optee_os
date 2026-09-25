/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GCC_BASE			UL(0x110000)
#define GCC_SIZE			UL(0x100000)

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

#define TURING_0_BASE			UL(0x24000000)
#define TURING_0_SIZE			UL(0x03000000)

#define TURING_GDSP_0_BASE		UL(0x20000000)
#define TURING_GDSP_0_SIZE		UL(0x01000000)

#define LPASS_BASE			UL(0x02c00000)
#define LPASS_SIZE			ULL(0x01080000)

/* CDSP content-protection shared channel, in TZ_STAT (secure DDR) */
#define CDSP_SECCHANNEL_BASE		UL(0xdb1dc000)
#define CDSP_SECCHANNEL_SIZE		UL(0x2000)

#define AOSS_CC_BASE			UL(0x0c2a8000)
#define AOSS_CC_SIZE			UL(0x00050000)

#define RPMH_PDC_GLOBAL_BASE		UL(0x0b5e0000)
#define RPMH_PDC_GLOBAL_SIZE		UL(0x00002000)

#define RPMH_PDC_COMPUTE_BASE		UL(0x0b2c0000)
#define RPMH_PDC_COMPUTE_SIZE		UL(0x00002000)

#define RPMH_PDC_GPDSP0_BASE		UL(0x0b240000)
#define RPMH_PDC_GPDSP0_SIZE		UL(0x00002000)

#define RPMH_PDC_AUDIO_BASE		UL(0x0b250000)
#define RPMH_PDC_AUDIO_SIZE		UL(0x00002000)

#define TCSR_SPARE_RG63_WO_1		UL(0x01fff018)

#endif /* TARGET_CONFIG_H */
