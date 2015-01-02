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

#ifndef TEE_MM_DEF_H
#define TEE_MM_DEF_H

#define SMALL_PAGE_SHIFT	12
#define SMALL_PAGE_MASK		0x00000fff
#define SMALL_PAGE_SIZE		0x00001000

/* define section to load */
#define TEE_DDR_VLOFFSET    0x1


/*
 * Register addresses related to time
 * RTT = Real-Time Timer
 * RTT0 = Real-Time Timer 0
 * RTT1 = Real-Time Timer 1
 */
#define RTT_CR_EN		0x2
#define RTT_CR_ENS		0x4
#define RTT_IMSC_IMSC		0x1
#define RTT_MIS_MIS		0x1

/* RTT0 definition */
#define RTT0_REG_START_ADDR	0x80152000
#define RTT0_CTCR		(RTT0_REG_START_ADDR)
#define RTT0_IMSC		(RTT0_REG_START_ADDR + 0x04)
#define RTT0_RIS		(RTT0_REG_START_ADDR + 0x08)
#define RTT0_MIS		(RTT0_REG_START_ADDR + 0x0C)
#define RTT0_ICR		(RTT0_REG_START_ADDR + 0x10)
#define RTT0_DR			(RTT0_REG_START_ADDR + 0x14)
#define RTT0_LR			(RTT0_REG_START_ADDR + 0x18)
#define RTT0_CR			(RTT0_REG_START_ADDR + 0x1c)

/* RTT1 definition */
#define RTT1_REG_START_ADDR	0x80153000
#define RTT1_CTCR		(RTT1_REG_START_ADDR)
#define RTT1_IMSC		(RTT1_REG_START_ADDR + 0x04)
#define RTT1_RIS		(RTT1_REG_START_ADDR + 0x08)
#define RTT1_MIS		(RTT1_REG_START_ADDR + 0x0C)
#define RTT1_ICR		(RTT1_REG_START_ADDR + 0x10)
#define RTT1_DR			(RTT1_REG_START_ADDR + 0x14)
#define RTT1_LR			(RTT1_REG_START_ADDR + 0x18)
#define RTT1_CR			(RTT1_REG_START_ADDR + 0x1c)

#endif
