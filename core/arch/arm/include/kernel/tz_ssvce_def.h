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
 * ARMv7 Secure Services library
 */

#define CPSR_OFFSET                0x00
#define STACK_INT_USAGE            0x04

/*
 * tee service IDs (TODO: align with the service ID list).
 * Set by NSec in R4 before SMC to request a TEE service.
 */
#define SSAPI_RET_FROM_INT_SERV             4
#define SSAPI_RET_FROM_RPC_SERV             5

/*
 * TEE monitor: status returned by the routine that checks the entry
 * reason (valid Service ID / secure context).
 */
#define SEC_INVALID_ENTRY                  0
#define SEC_PRE_INIT_ENTRY                 1
#define SEC_RET_FROM_INT_ENTRY             2
#define SEC_RET_FROM_RPC_ENTRY             3
#define SEC_NORMAL_ENTRY                   4

/*
 * teecore exit reason.
 * Set by Secure in R4 before SMC to request a switch to NSec.
 */
#define SEC_EXIT_NORMAL                    1
#define SEC_EXIT_START_EXT_CODE            2
#define SEC_EXIT_INT                       3
#define SEC_EXIT_RPC_CALL                  4
#define SEC_EXIT_FIRST                     5
#define SEC_EXIT_DEEP_SLEEP                6

/* misc */

#define  SEC_UNDEF_STACK_OFFSET             4
#define  SEC_ABORT_STACK_OFFSET             12

#define  SEC_ENTRY_STATUS_NOK             0
#define  SEC_ENTRY_STATUS_OK              1

/* Various IOMEM location */
#include <platform_config.h>

/*
 * Outer cache iomem
 */
#define PL310_LINE_SIZE		32
#define PL310_NB_WAYS		8

#define PL310_BASE_H	((PL310_BASE >> 16) & 0xFFFF)
#define PL310_BASE_L	(PL310_BASE & 0xFFFF)
/* reg1 */
#define PL310_CTRL		(PL310_BASE_L | 0x100)
#define PL310_AUX_CTRL		(PL310_BASE_L | 0x104)
#define PL310_TAG_RAM_CTRL	(PL310_BASE_L | 0x108)
#define PL310_DATA_RAM_CTRL	(PL310_BASE_L | 0x10C)
/* reg7 */
#define PL310_SYNC		(PL310_BASE_L | 0x730)
#define PL310_INV_BY_WAY	(PL310_BASE_L | 0x77C)
#define PL310_CLEAN_BY_WAY	(PL310_BASE_L | 0x7BC)
#define PL310_FLUSH_BY_WAY	(PL310_BASE_L | 0x7FC)
#define PL310_INV_BY_PA		(PL310_BASE_L | 0x770)
#define PL310_CLEAN_BY_PA	(PL310_BASE_L | 0x7B0)
#define PL310_FLUSH_BY_PA	(PL310_BASE_L | 0x7F0)
#define PL310_FLUSH_BY_INDEXWAY	(PL310_BASE_L | 0x7F8)
/* reg9 */
#define PL310_DCACHE_LOCKDOWN_BASE (PL310_BASE_L | 0x900)
#define PL310_ICACHE_LOCKDOWN_BASE (PL310_BASE_L | 0x904)
/* reg12 */
#define PL310_ADDR_FILT_START	(PL310_BASE_L | 0xC00)
#define PL310_ADDR_FILT_END	(PL310_BASE_L | 0xC04)
/* reg15 */
#define PL310_DEBUG_CTRL	(PL310_BASE_L | 0xF40)
#define PL310_PREFETCH_CTRL	(PL310_BASE_L | 0xF60)
#define PL310_POWER_CTRL	(PL310_BASE_L | 0xF80)

/*
 * SCU iomem
 */
#define SCU_BASE_H	((SCU_BASE >> 16) & 0xFFFF)
#define SCU_BASE_L	(SCU_BASE & 0xFFFF)

#define SCU_CTRL	(SCU_BASE_L | 0x00)
#define SCU_CONFIG	(SCU_BASE_L | 0x04)
#define SCU_POWER	(SCU_BASE_L | 0x08)
#define SCU_INV_SEC	(SCU_BASE_L | 0x0C)
#define SCU_FILT_SA	(SCU_BASE_L | 0x40)
#define SCU_FILT_EA	(SCU_BASE_L | 0x44)
#define SCU_SAC		(SCU_BASE_L | 0x50)
#define SCU_NSAC	(SCU_BASE_L | 0x54)
#define SCU_ERRATA744369	(SCU_BASE_L | 0x30)

/*
 * GIC iomem
 */
#define GIC_DIST_BASE_H	((GIC_DIST_BASE >> 16) & 0xFFFF)
#define GIC_DIST_BASE_L	(GIC_DIST_BASE & 0xFFFF)

#define GIC_DIST_ISR0	(GIC_DIST_BASE_L | 0x080)
#define GIC_DIST_ISR1	(GIC_DIST_BASE_L | 0x084)

/*
 * CPU iomem
 */
#define GIC_CPU_BASE_H	((GIC_CPU_BASE >> 16) & 0xFFFF)
#define GIC_CPU_BASE_L	(GIC_CPU_BASE & 0xFFFF)

#define CORE_ICC_ICCPMR	(GIC_CPU_BASE_L | 0x0004)
