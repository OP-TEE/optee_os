// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
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

#include <arm.h>
#include <arm32.h>
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mmdc.h>
#include <platform_config.h>
#include <stdint.h>

int imx_get_ddr_type(void)
{
	uint32_t val, off;
	bool is_mx7 = soc_is_imx7ds();
	vaddr_t mmdc_base = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC);

	if (is_mx7)
		off = DDRC_MSTR;
	else
		off = MMDC_MDMISC;

	val =  read32(mmdc_base + off);

	if (is_mx7) {
		if (val & MSTR_DDR3)
			return IMX_DDR_TYPE_DDR3;
		else if (val & MSTR_LPDDR2)
			return IMX_DDR_TYPE_LPDDR2;
		else if (val & MSTR_LPDDR3)
			return IMX_DDR_TYPE_LPDDR3;
		else
			return -1;
	}

	return (val & MDMISC_DDR_TYPE_MASK) >> MDMISC_DDR_TYPE_SHIFT;
}
