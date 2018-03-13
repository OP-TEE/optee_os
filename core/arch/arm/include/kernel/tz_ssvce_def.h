/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TZ_SSVCE_DEF_H
#define TZ_SSVCE_DEF_H

#include <util.h>

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

/*
 * Outer cache iomem
 */
#define PL310_LINE_SIZE		32
#define PL310_8_WAYS		8

/* reg1 */
#define PL310_CTRL		0x100
#define PL310_AUX_CTRL		0x104
#define PL310_TAG_RAM_CTRL	0x108
#define PL310_DATA_RAM_CTRL	0x10C
/* reg7 */
#define PL310_SYNC		0x730
#define PL310_INV_BY_WAY	0x77C
#define PL310_CLEAN_BY_WAY	0x7BC
#define PL310_FLUSH_BY_WAY	0x7FC
#define PL310_INV_BY_PA		0x770
#define PL310_CLEAN_BY_PA	0x7B0
#define PL310_FLUSH_BY_PA	0x7F0
#define PL310_FLUSH_BY_INDEXWAY	0x7F8
/* reg9 */
#define PL310_DCACHE_LOCKDOWN_BASE 0x900
#define PL310_ICACHE_LOCKDOWN_BASE 0x904
/* reg12 */
#define PL310_ADDR_FILT_START	0xC00
#define PL310_ADDR_FILT_END	0xC04
/* reg15 */
#define PL310_DEBUG_CTRL	0xF40
#define PL310_PREFETCH_CTRL	0xF60
#define PL310_POWER_CTRL	0xF80

#define PL310_CTRL_ENABLE_BIT	BIT32(0)
#define PL310_AUX_16WAY_BIT	BIT32(16)

/*
 * SCU iomem
 */
#define SCU_CTRL	0x00
#define SCU_CONFIG	0x04
#define SCU_POWER	0x08
#define SCU_INV_SEC	0x0C
#define SCU_FILT_SA	0x40
#define SCU_FILT_EA	0x44
#define SCU_SAC		0x50
#define SCU_NSAC	0x54
#define SCU_ERRATA744369 0x30

#define SCU_ACCESS_CONTROL_CPU0		BIT32(0)
#define SCU_ACCESS_CONTROL_CPU1		BIT32(1)
#define SCU_ACCESS_CONTROL_CPU2		BIT32(2)
#define SCU_ACCESS_CONTROL_CPU3		BIT32(3)
#define SCU_NSAC_SCU_SHIFT		0
#define SCU_NSAC_PTIMER_SHIFT		4
#define SCU_NSAC_GTIMER_SHIFT		8

/*
 * GIC iomem
 */
#define GIC_DIST_ISR0	0x080
#define GIC_DIST_ISR1	0x084
#define GIC_DIST_IPRIO	0x400

/*
 * CPU iomem
 */
#define CORE_ICC_ICCPMR	0x0004

#endif /* TZ_SSVCE_DEF_H */
