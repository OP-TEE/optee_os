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

#include <io.h>
#include <trace.h>
#include <kernel/interrupt.h>
#include "rcar_ddr_training.h"
#include "rcar_common.h"

void ddr_training_timer_init(void)
{
	uint16_t sr;
	uint32_t interval_ms;
	uint32_t count;
	uint32_t mdpin_data;
	uint32_t oscclk_hz;
	const uint16_t clear_mask = (uint16_t)~(
			CMSCSR_BIT_CMF | CMSCSR_BIT_CMM |
			CMSCSR_BIT_CMR | CMSCSR_BIT_CKS);

	/* Timer stop */
	write16(0x0000U, CMSSTR);

	/* Set clock select and compare match mode */
	sr = read16(CMSCSR);
	sr &= clear_mask;
	sr |= (CMM_FREE_RUN_OPERATION
		| CMR_INTERRUPT_ENABLE
		| CKS_DIVISION_RATIO_1);
	write16(sr, CMSCSR);

	/* Set timer interval [ms] */
	interval_ms = 20U;	/* T.B.D */

	/* Set the frequency of OSCCLK */
	mdpin_data = read32(MODEMR) & CHECK_MD13_MD14;
	switch (mdpin_data) {
	case MD14_L_MD13_H:
		oscclk_hz = 131570U;	/* 131.57kHz */
		break;
	default:
		oscclk_hz = 130200U;	/* 130.20kHz */
		break;
	}

	/* Calculate the match count */
	count = (interval_ms * oscclk_hz) / 1000U;

	/* Set match count */
	write32(count, CMSCOR);
}

static enum itr_return ddr_training_itr_cb(struct itr_handler *h __unused)
{
	ddr_training_execute();
	return ITRR_HANDLED;
}

static struct itr_handler ddr_training_itr = {
	.it = INTID_SCMT,
	.flags = ITRF_TRIGGER_LEVEL,
	.handler = ddr_training_itr_cb,
};

void ddr_training_timer_start(void)
{
	/* Enable GIC - System Timer*/
	itr_add(&ddr_training_itr);
	itr_enable(&ddr_training_itr);
	/* Counter reset */
	write32(0x00000000U, CMSCNT);

	/* Timer start */
	write16(CMSSTR_BIT_STR5, CMSSTR);
}

void ddr_training_execute(void)
{
	uint16_t sr;
	const uint16_t clear_mask = (uint16_t)~(
			CMSCSR_BIT_CMF | CMSCSR_BIT_OVF);

	/* Clear an internal interrupt request */
	sr = read16(CMSCSR);
	sr &= clear_mask;
	write16(sr, CMSCSR);

	/* Dummy read */
	(void)read16(CMSCSR);

	/* T.B.D. */
}
