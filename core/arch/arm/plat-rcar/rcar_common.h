/*
 * Copyright (c) 2015-2016, Renesas Electronics Corporation
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

#ifndef RCAR_COMMON_H
#define RCAR_COMMON_H

#include <string.h>
#include <platform_config.h>
#include <kernel/misc.h>
#include <kernel/tz_proc.h>
#include <kernel/panic.h>
#include <drivers/gic.h>
#include <arm.h>
#include <kernel/tee_time.h>

/* System Timer Register */
#define CMSSTR			(SYSTIM_BASE + 0x000U)
#define CMSCSR			(SYSTIM_BASE + 0x040U)
#define CMSCNT			(SYSTIM_BASE + 0x044U)
#define CMSCOR			(SYSTIM_BASE + 0x048U)

#define CMSSTR_BIT_STR5		(0x0020U)	/* CMSSTR Bit 5   */

#define CMSCSR_BIT_CMF		(0x8000U)	/* CMSCSR Bit 15  */
#define CMSCSR_BIT_OVF		(0x4000U)	/* CMSCSR Bit 14  */
#define CMSCSR_BIT_WRFLG	(0x2000U)	/* CMSCSR Bit 13  */
#define CMSCSR_BIT_CMS		(0x0200U)	/* CMSCSR Bit 9   */
#define CMSCSR_BIT_CMM		(0x0100U)	/* CMSCSR Bit 8   */
#define CMSCSR_BIT_CMR		(0x0030U)	/* CMSCSR Bit 4-5 */
#define CMSCSR_BIT_DBGIVD	(0x0008U)	/* CMSCSR Bit 3   */
#define CMSCSR_BIT_CKS		(0x0007U)	/* CMSCSR Bit 0-2 */

#define CKS_DIVISION_RATIO_1	(0x7U)		/* CKS clock/1    */
#define CKS_DIVISION_RATIO_8	(0x4U)		/* CKS clock/8    */
#define CKS_DIVISION_RATIO_32	(0x5U)		/* CKS clock/32   */
#define CKS_DIVISION_RATIO_128	(0x6U)		/* CKS clock/128  */
#define CMR_INTERRUPT_ENABLE	(0x20U)		/* CMR Interrupt Enable */
#define CMM_FREE_RUN_OPERATION	(0x100U)	/* CMM Free-running operation */
#define CMM_ONE_SHOT_OPERATION	(0x000U)	/* CMM One-shot operation     */

#define SYSTIM_PRIORITY		(0x1U)

/* Reset(RST) */
#define MODEMR			(0xE6160060U)	/* Mode Monitor Register */

#define CHECK_MD13_MD14		(0x6000U)
#define MD14_L_MD13_H		(0x2000U)

/* Interrupt ID */
#define INTID_SCMT		(134U + 32U)	/* System Timer */

/* RPC No specific to R-Car */
#define TEE_RPC_DEBUG_LOG	(0x3F000000U)

/*
 * Prototype declaration
 */

void cpu_spin_lock_irqsave(uint32_t *lock, uint32_t *flags);
void cpu_spin_unlock_irqrestore(uint32_t *lock, uint32_t flags);

uint32_t disable_interrupts(void);
void enable_interrupts(uint32_t flags);
void enable_abort(void);
void enable_fiq(void);
void enable_irq(void);

#endif /* RCAR_COMMON_H */
