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
 * LPASS / ADSP (QDSP6 v68/v69) subsystem. Base mirrors the TZ HWIO layout
 * (LPASS_BASE in msmhwiobase.h); the window covers every LPASS sub-block the
 * PTA and clock driver touch (PUB 0x400000, PLL 0x440000, CORE_CC 0x448000,
 * AON_CC 0x808000, MCC/EFUSE 0x8d0000, CORE_GDSC/TOP_CC 0x1000000).
 */
#define LPASS_BASE			UL(0x02c00000)
#define LPASS_SIZE			ULL(0x01080000)

/*
 * IRIS video-codec subsystem. Base/size mirror the TZ HWIO layout
 * (IRIS_BASE / IRIS_BASE_SIZE in msmhwiobase.h); the window covers the
 * VCODEC_IRIS_WRAPPER_TOP (IRIS+0xb0000) and WRAPPER_TZ (IRIS+0xc0000) blocks
 * the bring-up path touches.
 */
#define IRIS_BASE			UL(0x0aa00000)
#define IRIS_SIZE			ULL(0x00200000)

#define PAS_ID_TURING			18
#define PAS_ID_TURING1			30
#define PAS_ID_QDSP6			1
#define PAS_ID_IRIS			9

/*
 * CDSP (CDSP0 / TURING) content-protection shared channel in the static TZ DDR
 * region. TZ zeroes this on CDSP0 bring-up (ACResetSharedChannel,
 * AC_VM_CP_CDSP); there is no equivalent CDSP1 channel. Address mirrors the TZ
 * DDR layout: TZBSP_EBI1_SECCHANNEL_CDSP (TZ_TZ_STAT_BASE_ADDR 0xDB100000 +
 * 0xc0000 + TZBSP_TZ_DDR_SECCHANNEL_SIZE 0x1c000), size 0x2000.
 */
#define CDSP_SECCHANNEL_BASE		UL(0xdb1dc000)
#define CDSP_SECCHANNEL_SIZE		UL(0x2000)

/*
 * Global register blocks used by the Turing/NSP subsystem reset sequence
 * (Reset_TURINGProcessor / Reset_TURING1Processor in the reference ClockPIL).
 * AOSS_CC and the RPMH PDC blocks live under AOSS_BASE (0x0b000000). The TCSR
 * mutex block (TCSR_MUTEX_BASE / TCSR_MUTEX_SIZE) is already defined in
 * arch_config.h. A single window per block is mapped; sizes cover the
 * registers the reset sequence touches.
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
