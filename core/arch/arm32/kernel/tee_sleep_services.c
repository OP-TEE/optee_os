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

#include <kernel/tee_sleep_services.h>


#ifdef DMAC_PREFOT_REG_ADDR
static uint32_t dmac_prefot;
#endif

#if defined(DMAC_SWSEG_START_ADDR) && defined(DMAC_SWDEG_START_ADDR)
static uint32_t dmac_swseg[DMAC_SWSREG_NUM_REGS];
static uint32_t dmac_swdeg[DMAC_SWDREG_NUM_REGS];
#endif

TEE_Result tee_sleep_save_restore_vape(bool save)
{
#ifdef DMAC_PREFOT_REG_ADDR
	if (save)
		dmac_prefot = IO(DMAC_PREFOT_REG_ADDR);
	else
		IO(DMAC_PREFOT_REG_ADDR) = dmac_prefot;
#endif

#if defined(DMAC_SWSEG_START_ADDR) && defined(DMAC_SWDEG_START_ADDR)
	{
		uint32_t i;

		if (save) {
			for (i = 0; i < DMAC_SWSREG_NUM_REGS; i++)
				dmac_swseg[i] =
				    IO(DMAC_SWSEG_START_ADDR + i * 4);
			for (i = 0; i < DMAC_SWDREG_NUM_REGS; i++)
				dmac_swdeg[i] =
				    IO(DMAC_SWDEG_START_ADDR + i * 4);
		} else {
			for (i = 0; i < DMAC_SWSREG_NUM_REGS; i++)
				IO(DMAC_SWSEG_START_ADDR + i * 4) =
				    dmac_swseg[i];
			for (i = 0; i < DMAC_SWDREG_NUM_REGS; i++)
				IO(DMAC_SWDEG_START_ADDR + i * 4) =
				    dmac_swdeg[i];
		}
	}
#endif

	return TEE_SUCCESS;
}
