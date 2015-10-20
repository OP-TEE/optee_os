/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *  General constants
 */

/*
 * CP15 Multiprocessor Affinity register (MPIDR)
 */
#define CP15_CONFIG_CPU_ID_MASK   0x00000003
#define CPU_ID0    0x00000000
#define CPU_ID1    0x00000001

/*
 * CP15 Secure configuration register
 */
#define CP15_CONFIG_NS_MASK   0x00000001
#define CP15_CONFIG_IRQ_MASK  0x00000002
#define CP15_CONFIG_FIQ_MASK  0x00000004
#define CP15_CONFIG_EA_MASK   0x00000008
#define CP15_CONFIG_FW_MASK   0x00000010
#define CP15_CONFIG_AW_MASK   0x00000020
#define CP15_CONFIG_nET_MASK  0x00000040

/*
 * CP15 Control register
 */
#define CP15_CONTROL_M_MASK          0x00000001
#define CP15_CONTROL_C_MASK          0x00000004
#define CP15_CONTROL_Z_MASK          0x00000800
#define CP15_CONTROL_I_MASK          0x00001000
#define CP15_CONTROL_V_MASK          0x00002000
#define CP15_CONTROL_HA_MASK         0x00020000
#define CP15_CONTROL_EE_MASK         0x02000000
#define CP15_CONTROL_NMFI_MASK       0x08000000
#define CP15_CONTROL_TRE_MASK        0x10000000
#define CP15_CONTROL_AFE_MASK        0x20000000
#define CP15_CONTROL_TE_MASK         0x40000000

/*
 * CP15 Auxiliary Control register
 */
#define CP15_CONTROL_SMP_MASK        0x00000040
#define CP15_CONTROL_EXCL_MASK       0x00000080

/*
 * CP15 Non secure access control register
 */
#define CP15_NSAC_TL_MASK        0x10000
#define CP15_NSAC_CL_MASK        0x20000
#define CP15_NSAC_CPN_MASK       0x3FFF

/*
 * CP15 Cache register
 */
#define CP15_CACHE_ADDR_R_BIT    12
#define CP15_CACHE_ADDR_L_BIT    (32-CP15_CACHE_ADDR_R_BIT)
#define CP15_CACHE_RESULT_MASK   0x00000001

/*
 * CP15 TCM register
 *
 * ITCM configuration (4kbytes, @0x20100000, enabled)
 * DTCM configuration (4kbytes, @0x20101000, enabled)
 */
#define CP15_TCM_ENABLE_MASK     0x00000001
#define CP15_TCM_INSTR_TCM       0x2010000C
#define CP15_TCM_DATA_TCM        0x2010100C

/*
 * CP15 cache lockdown register
 *
 * ITCM configuration (4kbytes, @0x20100000, enabled)
 * DTCM configuration (4kbytes, @0x20101000, enabled)
 */
#define CP15_CACHE_LOCK_ALLWAYS_MASK     0x0000000F

/*
 * CP15 cache cleaning constant definition
 */
/* start of line number field offset in way/index format */
#define LINE_FIELD_OFFSET        5
/* Warning: this assumes a 256 lines/way cache (32kB cache) */
#define LINE_FIELD_OVERFLOW      13
/* start of way number field offset in way/index format */
#define WAY_FIELD_OFFSET         30
