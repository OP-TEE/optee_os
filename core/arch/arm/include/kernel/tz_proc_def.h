/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_TZ_PROC_DEF_H
#define __KERNEL_TZ_PROC_DEF_H

#include <stdint.h>

/*
 *  General constants
 */

/*
 * CP15 Multiprocessor Affinity register (MPIDR)
 */
#define CP15_CONFIG_CPU_ID_MASK   U(0x00000003)
#define CPU_ID0    U(0x00000000)
#define CPU_ID1    U(0x00000001)

/*
 * CP15 Secure configuration register
 */
#define CP15_CONFIG_NS_MASK   U(0x00000001)
#define CP15_CONFIG_IRQ_MASK  U(0x00000002)
#define CP15_CONFIG_FIQ_MASK  U(0x00000004)
#define CP15_CONFIG_EA_MASK   U(0x00000008)
#define CP15_CONFIG_FW_MASK   U(0x00000010)
#define CP15_CONFIG_AW_MASK   U(0x00000020)
#define CP15_CONFIG_nET_MASK  U(0x00000040)

/*
 * CP15 Control register
 */
#define CP15_CONTROL_M_MASK          U(0x00000001)
#define CP15_CONTROL_C_MASK          U(0x00000004)
#define CP15_CONTROL_Z_MASK          U(0x00000800)
#define CP15_CONTROL_I_MASK          U(0x00001000)
#define CP15_CONTROL_V_MASK          U(0x00002000)
#define CP15_CONTROL_HA_MASK         U(0x00020000)
#define CP15_CONTROL_EE_MASK         U(0x02000000)
#define CP15_CONTROL_NMFI_MASK       U(0x08000000)
#define CP15_CONTROL_TRE_MASK        U(0x10000000)
#define CP15_CONTROL_AFE_MASK        U(0x20000000)
#define CP15_CONTROL_TE_MASK         U(0x40000000)

/*
 * CP15 Auxiliary Control register
 */
#define CP15_CONTROL_SMP_MASK        U(0x00000040)
#define CP15_CONTROL_EXCL_MASK       U(0x00000080)

/*
 * CP15 Non secure access control register
 */
#define CP15_NSAC_TL_MASK        U(0x10000)
#define CP15_NSAC_CL_MASK        U(0x20000)
#define CP15_NSAC_CPN_MASK       U(0x3FFF)

/*
 * CP15 Cache register
 */
#define CP15_CACHE_ADDR_R_BIT    U(12)
#define CP15_CACHE_ADDR_L_BIT    (U(32) - CP15_CACHE_ADDR_R_BIT)
#define CP15_CACHE_RESULT_MASK   U(0x00000001)

/*
 * CP15 TCM register
 *
 * ITCM configuration (4kbytes, @0x20100000, enabled)
 * DTCM configuration (4kbytes, @0x20101000, enabled)
 */
#define CP15_TCM_ENABLE_MASK     U(0x00000001)
#define CP15_TCM_INSTR_TCM       U(0x2010000C)
#define CP15_TCM_DATA_TCM        U(0x2010100C)

/*
 * CP15 cache lockdown register
 *
 * ITCM configuration (4kbytes, @0x20100000, enabled)
 * DTCM configuration (4kbytes, @0x20101000, enabled)
 */
#define CP15_CACHE_LOCK_ALLWAYS_MASK     U(0x0000000F)

/*
 * CP15 cache cleaning constant definition
 */
/* start of line number field offset in way/index format */
#define LINE_FIELD_OFFSET        U(5)
/* Warning: this assumes a 256 lines/way cache (32kB cache) */
#define LINE_FIELD_OVERFLOW      U(13)
/* start of way number field offset in way/index format */
#define WAY_FIELD_OFFSET         U(30)

#endif /*__KERNEL_TZ_PROC_DEF_H*/
