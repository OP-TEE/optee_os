/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

/*
 * Clock controllers. Nord splits its QUPv3 serial engines across the SE and NE
 * quadrant controllers, each with its own GPLL0 and vote registers, alongside
 * the central GCC that owns QUPv3 wrapper 3. The NW quadrant controller has no
 * QUP serial engines, so it is not mapped.
 */
#define GCC_BASE			UL(0x00110000)
#define GCC_SIZE			UL(0x001e0000)

#define SE_GCC_BASE			UL(0x08a10000)
#define SE_GCC_SIZE			UL(0x000e0000)

#define NE_GCC_BASE			UL(0x08910000)
#define NE_GCC_SIZE			UL(0x000e0000)

#define RAMBLUR_PIMEM_REG_BASE		UL(0x610000)

#define SECURITY_CONTROL_BASE		UL(0x00780000)
#define SECURITY_CONTROL_SIZE		UL(0x10000)

#define GENI_UART_REG_BASE		UL(0x884000)

#define GICD_BASE			UL(0x17000000)
#define GICR_BASE			UL(0x17080000)
#define AOP_CMD_DB_BASE			UL(0x87148000)

#define AOP_CMD_DB_SIZE			UL(0x2000)

#define AOP_MSG_RAM_BASE		UL(0x0C300000)
#define AOP_MSG_RAM_SIZE		UL(0x00100000)
#define MSG_RAM_SECTION_SIZE            UL(0x00001000)

#define RPMH_BASE_ADDR			UL(0x18900000)
#define RPMH_RSC_SIZE			UL(0x10000)

/*
 * AOSS_CC reset control, which owns the SOCCP subsystem-restart registers, and
 * the SOCCP CSR window holding its boot-suppress register.
 */
#define AOSS_CC_BASE			UL(0x0c2f0000)
#define AOSS_CC_SIZE			UL(0x00010000)

#define SOCCP_CSR_BASE			UL(0x00d40000)
#define SOCCP_CSR_SIZE			UL(0x0007f000)

#define SEC_PRNG_REG_BASE		UL(0x010d1000)

#define TCSR_MUTEX_BASE			UL(0x01f40000)
#define TCSR_MUTEX_SIZE			UL(0xc0000)

#define HPASS_0_BASE			UL(0x04c00000)
#define HPASS_0_SIZE			UL(0x00100000)

#define HPASS_CC_BASE			UL(0x05508000)
#define HPASS_CC_SIZE			UL(0x00020000)

#define HPASS_TCSR_BASE			UL(0x05580000)
#define HPASS_TCSR_SIZE			UL(0x00020000)

#define HPASS_TCM_BASE			UL(0x05700000)
#define HPASS_TCM_SIZE			UL(0x00001000)

#define HPASS_1_BASE			UL(0x06000000)
#define HPASS_1_SIZE			UL(0x00100000)

#define HPASS_2_BASE			UL(0x06100000)
#define HPASS_2_SIZE			UL(0x00100000)

#define RPMH_PDC_GLOBAL_BASE		UL(0x0b5e6000)
#define RPMH_PDC_GLOBAL_SIZE		UL(0x0000a000)

#define QDSS_SOCCP_DMI_BASE		UL(0x11508000)
#define QDSS_SOCCP_DMI_SIZE		UL(0x00001000)

#define IMEM_BASE			UL(0x14680000)
#define IMEM_SIZE			UL(0x32000)

#define CDSP_0_BASE			UL(0x1f0c8000)
#define CDSP_0_SIZE			UL(0x00280000)

#define CDSP_1_BASE			UL(0x1f4c8000)
#define CDSP_1_SIZE			UL(0x00280000)

#define CDSP_2_BASE			UL(0x1f8c8000)
#define CDSP_2_SIZE			UL(0x00280000)

#define CDSP_3_BASE			UL(0x1fcc8000)
#define CDSP_3_SIZE			UL(0x00280000)

#define FUSE_CONTROLLER_SW_RANGE4_BASE	UL(0x360d4000)
#define FUSE_CONTROLLER_SW_RANGE4_SIZE	UL(0x00001000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE                     UL(0x80000000)
#define DRAM1_BASE                     ULL(0x880000000)
#define DRAM1_SIZE                     ULL(0x780000000)
#define DRAM2_BASE                     ULL(0x8800000000)
#define DRAM2_SIZE                     ULL(0x3800000000)

#define TLMM_BASE                      UL(0x0f000000)
#define TLMM_BASE_SIZE                 UL(0x01000000)

#endif /* TARGET_CONFIG_H */
