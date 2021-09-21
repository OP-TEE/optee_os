/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TZ_SSVCE_DEF_H
#define TZ_SSVCE_DEF_H

#include <stdint.h>
#include <util.h>

/*
 * ARMv7 Secure Services library
 */

#define CPSR_OFFSET                U(0x00)
#define STACK_INT_USAGE            U(0x04)

/*
 * tee service IDs (TODO: align with the service ID list).
 * Set by NSec in R4 before SMC to request a TEE service.
 */
#define SSAPI_RET_FROM_INT_SERV             U(4)
#define SSAPI_RET_FROM_RPC_SERV             U(5)

/*
 * TEE monitor: status returned by the routine that checks the entry
 * reason (valid Service ID / secure context).
 */
#define SEC_INVALID_ENTRY                  U(0)
#define SEC_PRE_INIT_ENTRY                 U(1)
#define SEC_RET_FROM_INT_ENTRY             U(2)
#define SEC_RET_FROM_RPC_ENTRY             U(3)
#define SEC_NORMAL_ENTRY                   U(4)

/*
 * teecore exit reason.
 * Set by Secure in R4 before SMC to request a switch to NSec.
 */
#define SEC_EXIT_NORMAL                    U(1)
#define SEC_EXIT_START_EXT_CODE            U(2)
#define SEC_EXIT_INT                       U(3)
#define SEC_EXIT_RPC_CALL                  U(4)
#define SEC_EXIT_FIRST                     U(5)
#define SEC_EXIT_DEEP_SLEEP                U(6)

/* misc */

#define  SEC_UNDEF_STACK_OFFSET             U(4)
#define  SEC_ABORT_STACK_OFFSET             U(12)

#define  SEC_ENTRY_STATUS_NOK             U(0)
#define  SEC_ENTRY_STATUS_OK              U(1)

/*
 * Outer cache iomem
 */
#define PL310_LINE_SIZE		U(32)
#define PL310_8_WAYS		U(8)

#define PL310_CACHE_ID		0x0
/* reg1 */
#define PL310_CTRL		U(0x100)
#define PL310_AUX_CTRL		U(0x104)
#define PL310_TAG_RAM_CTRL	U(0x108)
#define PL310_DATA_RAM_CTRL	U(0x10C)
/* reg7 */
#define PL310_SYNC		U(0x730)
#define PL310_INV_BY_WAY	U(0x77C)
#define PL310_CLEAN_BY_WAY	U(0x7BC)
#define PL310_FLUSH_BY_WAY	U(0x7FC)
#define PL310_INV_BY_PA		U(0x770)
#define PL310_CLEAN_BY_PA	U(0x7B0)
#define PL310_FLUSH_BY_PA	U(0x7F0)
#define PL310_FLUSH_BY_INDEXWAY	U(0x7F8)
/* reg9 */
#define PL310_DCACHE_LOCKDOWN_BASE U(0x900)
#define PL310_ICACHE_LOCKDOWN_BASE U(0x904)
/* reg12 */
#define PL310_ADDR_FILT_START	U(0xC00)
#define PL310_ADDR_FILT_END	U(0xC04)
/* reg15 */
#define PL310_DEBUG_CTRL	U(0xF40)
#define PL310_PREFETCH_CTRL	U(0xF60)
#define PL310_POWER_CTRL	U(0xF80)

#define PL310_CTRL_ENABLE_BIT	BIT32(0)
#define PL310_AUX_16WAY_BIT	BIT32(16)

#define PL310_CACHE_ID_PART_MASK	GENMASK_32(9, 6)
#define PL310_CACHE_ID_PART_L310	0xC0
#define PL310_CACHE_ID_RTL_MASK		GENMASK_32(5, 0)
#define PL310_CACHE_ID_RTL_R3P2		0x8

/*
 * SCU iomem
 */
#define SCU_CTRL	U(0x00)
#define SCU_CONFIG	U(0x04)
#define SCU_POWER	U(0x08)
#define SCU_INV_SEC	U(0x0C)
#define SCU_FILT_SA	U(0x40)
#define SCU_FILT_EA	U(0x44)
#define SCU_SAC		U(0x50)
#define SCU_NSAC	U(0x54)
#define SCU_SIZE	U(0x58)
#define SCU_ERRATA744369 U(0x30)

#define SCU_ACCESS_CONTROL_CPU0		BIT32(0)
#define SCU_ACCESS_CONTROL_CPU1		BIT32(1)
#define SCU_ACCESS_CONTROL_CPU2		BIT32(2)
#define SCU_ACCESS_CONTROL_CPU3		BIT32(3)
#define SCU_NSAC_SCU_SHIFT		U(0)
#define SCU_NSAC_PTIMER_SHIFT		U(4)
#define SCU_NSAC_GTIMER_SHIFT		U(8)

/*
 * GIC iomem
 */
#define GIC_DIST_ISR0	U(0x080)
#define GIC_DIST_ISR1	U(0x084)
#define GIC_DIST_IPRIO	U(0x400)

/*
 * CPU iomem
 */
#define CORE_ICC_ICCPMR	U(0x0004)

#endif /* TZ_SSVCE_DEF_H */
