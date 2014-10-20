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
#include <trace.h>
#include <kernel/tee_misc_unpg.h>

/* Cut information for Orly2 */
/* SYSTEM_STATUS2600 = SAS Device ID :
   SYSCFGBaseAddress(0xFE830000)+ 0x00000960 */
/* SYSTEM_STATUS9516 = MPE Device ID :
   SYSCFGBaseAddress(0xFD690000)+ 0x00000810 */
/* [31:28] VERSION: Version
   [27:22] GROUP_ID: Group ID
   [21:12] DEVICE_ID: Device ID
   [11:1] MANUFACTURER_ID: Manufacturer ID
   [0] JTAG_BIT: JTAG b */

/* SYSTEM_STATUS9516 */
#define CUT_MPE_MAJOR_ADDR  0xfd690810
#define CUT_MPE_MAJOR_MASK  0xf0000000
#define CUT_MPE_MAJOR_SHIFT 28
#define ORLY2_MPE_MASK      0xFFFFFFFE
#define ORLY2_MPE_VALUE     0x0D44D040

/* SYSTEM_STATUS2600 */
#define CUT_SAS_MAJOR_ADDR  0xfe830960
#define CUT_SAS_MAJOR_MASK  0xf0000000
#define CUT_SAS_MAJOR_SHIFT 28
#define ORLY2_SAS_MASK      0xFFFFFFFE
#define ORLY2_SAS_VALUE     0x0D44C040

/* FUSE = MPE SAFMEM : 0xfd6d5000 */
/* 0x9C: eng_metal_fix_nb<3:0>
 * => ST Engineering setting. */
#define CUT_MPE_MINOR_ADDR  0xfd6d509c
#define CUT_MPE_MINOR_MASK  0xf
#define CUT_MPE_MINOR_SHIFT 0

uint32_t tee_get_cutid(void)
{
	uint32_t sas_major = 0, mpe_minor = 0, mpe_major = 0;
	uint32_t sas_major_val = 0, mpe_minor_val = 0, mpe_major_val = 0;
	uint32_t *sas_major_reg, *mpe_minor_reg, *mpe_major_reg;
	uint32_t result;

	/* Map major and minor registers */
	mpe_major_reg = tee_mmu_ioremap(CUT_MPE_MAJOR_ADDR, 4);
	sas_major_reg = tee_mmu_ioremap(CUT_SAS_MAJOR_ADDR, 4);
	mpe_minor_reg = tee_mmu_ioremap(CUT_MPE_MINOR_ADDR, 4);

	if ((mpe_major_reg != NULL) &&
	    (sas_major_reg != NULL) && (mpe_minor_reg != NULL)) {
		mpe_major_val = *mpe_major_reg;
		sas_major_val = *sas_major_reg;
		mpe_minor_val = *mpe_minor_reg;

		/* Read major revision */
		mpe_major = ((mpe_major_val & CUT_MPE_MAJOR_MASK) >>
			     CUT_MPE_MAJOR_SHIFT);

		/* Read major revision */
		sas_major = ((sas_major_val & CUT_SAS_MAJOR_MASK) >>
			     CUT_SAS_MAJOR_SHIFT);

		/* Read minor revision */
		mpe_minor = ((mpe_minor_val & CUT_MPE_MINOR_MASK) >>
			     CUT_MPE_MINOR_SHIFT);
	}

	/* Unmap */
	tee_mmu_iounmap(mpe_major_reg);
	tee_mmu_iounmap(sas_major_reg);
	tee_mmu_iounmap(mpe_minor_reg);

	DMSG("mpe_major_reg = 0x%x : 0x%x", (unsigned int)mpe_major_reg,
	     (unsigned int)mpe_major_val);
	DMSG("sas_major_reg = 0x%x : 0x%x", (unsigned int)sas_major_reg,
	     (unsigned int)sas_major_val);
	DMSG("mpe_minor_reg = 0x%x : 0x%x", (unsigned int)mpe_minor_reg,
	     (unsigned int)mpe_minor_val);

	/* Return a hex byte where
	 * [31:16] is chip name : 0x416 for orly2
	 * [15:12] is 0
	 * [11: 8] is [A-F] indicating MPE major number
	 * [ 7: 4] is [A-F] indicating SAS major number,
	 * [ 3: 0] is [0-9] indicating MPE minor number */
	if ((ORLY2_MPE_VALUE == (mpe_major_val & ORLY2_MPE_MASK)) &&
	    (ORLY2_SAS_VALUE == (sas_major_val & ORLY2_SAS_MASK)))
		result = ORLY2_CUTID_VAL + ((mpe_major * 0x100) +
					    ((sas_major * 0x10) + mpe_minor));
	else
		result = 0xFFFFFFFF;

	return result;
}
