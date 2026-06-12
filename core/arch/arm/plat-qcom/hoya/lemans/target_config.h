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

#define TURING_0_BASE			UL(0x24000000)
#define TURING_0_SIZE			UL(0x03000000)

#define TURING_1_BASE			UL(0x28000000)
#define TURING_1_SIZE			UL(0x03000000)

/*
 * LPASS / ADSP (QDSP6 v68/v69) subsystem window, covering every sub-block the
 * PTA and clock driver touch (PUB, PLL, CORE_CC, AON_CC, MCC, TOP_CC).
 */
#define LPASS_BASE			UL(0x02c00000)
#define LPASS_SIZE			ULL(0x01080000)

/*
 * IRIS video-codec subsystem. The window covers the VCODEC_IRIS_WRAPPER_TOP
 * (IRIS+0xb0000) and WRAPPER_TZ (IRIS+0xc0000) blocks the bring-up path
 * touches.
 */
#define IRIS_BASE			UL(0x0aa00000)
#define IRIS_SIZE			ULL(0x00200000)

#define PAS_ID_TURING			18
#define PAS_ID_TURING1			30
#define PAS_ID_QDSP6			1
#define PAS_ID_IRIS			9

/* CDSP0 content-protection shared channel (secure DDR); no CDSP1 equivalent. */
#define CDSP_SECCHANNEL_BASE		UL(0xdb1dc000)
#define CDSP_SECCHANNEL_SIZE		UL(0x2000)

/*
 * Global register blocks for the Turing/NSP reset sequence, under AOSS_BASE
 * (0x0b000000). TCSR_MUTEX_BASE/SIZE is already defined in arch_config.h.
 */
#define AOSS_CC_BASE			UL(0x0c2a8000)
#define AOSS_CC_SIZE			UL(0x00050000)

#define RPMH_PDC_GLOBAL_BASE		UL(0x0b5e0000)
#define RPMH_PDC_GLOBAL_SIZE		UL(0x00002000)

#define RPMH_PDC_COMPUTE_BASE		UL(0x0b2c0000)
#define RPMH_PDC_COMPUTE_SIZE		UL(0x00002000)

#define RPMH_PDC_NSP_BASE		UL(0x0b2f0000)
#define RPMH_PDC_NSP_SIZE		UL(0x00002000)

#endif /* TARGET_CONFIG_H */
