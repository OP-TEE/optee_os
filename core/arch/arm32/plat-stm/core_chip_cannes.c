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

#include <stdint.h>

#include <mm/tee_mmu_io.h>
#include <kernel/tee_core_trace.h>
#include <kernel/tee_misc_unpg.h>

/* Cut information for Cannes */
/* SYSTEM_STATUS5568 = Device ID :
   SYSCFGBaseAddress(0x092B0000)+ 0x000008E0 */

/* [31:28] VERSION: Version
   [27:22] GROUP_ID: Group ID
   [21:12] DEVICE_ID: Device ID
   [11:1] MANUFACTURER_ID: Manufacturer ID
   [0] JTAG_BIT: JTAG b */

/* SYSTEM_STATUS5568 */
#define CUT_MAJOR_ADDR  0x092B08E0
#define CUT_MAJOR_MASK  0xf0000000
#define CUT_MAJOR_SHIFT 28

#define CANNES_MASK     0x0FFFFFFE
#define CANNES_VALUE    0x0d450040

/* NVS : get from get_chip_cut_revision() in NOC */
/* TODO : get FUSE address and value for Cannes */
#define CUT_MINOR_ADDR      0xfd6d509c
#define CUT_MINOR_MASK      0xf
#define CUT_MINOR_SHIFT     0

uint32_t tee_get_cutid(void)
{
	uint32_t major = 0, minor = 0;
	uint32_t major_val = 0, minor_val = 0;
	uint32_t *major_reg, *minor_reg;
	uint32_t result;

	/* Map major and minor registers */
	major_reg = tee_mmu_ioremap(CUT_MAJOR_ADDR, 4);

	/* TODO : uncomment when address available */
	/* minor_reg = tee_mmu_ioremap(CUT_MINOR_ADDR, 4); */
	minor_reg = NULL;

	if (major_reg != NULL) {
		major_val = *major_reg;
		/* Read major revision */
		major = 1 + ((major_val & CUT_MAJOR_MASK) >> CUT_MAJOR_SHIFT);
		/* Unmap */
		tee_mmu_iounmap(major_reg);
	}
	if (minor_reg != NULL) {
		minor_val = *minor_reg;
		/* Read minor revision */
		minor = ((minor_val & CUT_MINOR_MASK) >> CUT_MINOR_SHIFT);
		/* Unmap */
		tee_mmu_iounmap(minor_reg);
	}

	DMSG("major_reg = 0x%x : 0x%x", (unsigned int)major_reg,
	     (unsigned int)major_val);
	DMSG("minor_reg = 0x%x : 0x%x", (unsigned int)minor_reg,
	     (unsigned int)minor_val);

	/* Return a hex byte where
	 * [31:16] is chip name : 0x305 for cannesgp
	 * [15:12] is 0
	 * [11: 8] is 0
	 * [ 7: 4] is [1-F] indicating major number,
	 * [ 3: 0] is [1-F] indicating minor number */
	if (CANNES_VALUE == (major_val & CANNES_MASK))
		result = CANNES_CUTID_VAL + (major * 0x10) + minor;
	else
		result = 0xFFFFFFFF;
	return result;
}
