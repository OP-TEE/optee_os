// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   CAAM Random Number Generator Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_ctrl.h>
#include <caam_hal_rng.h>
#include <caam_io.h>
#include <caam_status.h>
#include <registers/rng_regs.h>
#include <registers/version_regs.h>

enum caam_status __weak caam_hal_rng_instantiated(vaddr_t baseaddr)
{
	uint32_t vid = 0;
	uint32_t nb_sh = 0;
	uint32_t status = 0;

	/* RNG version < 4 and RNG state handle is already instantiated */
	if (caam_hal_ctrl_era(baseaddr) < 10) {
		vid = io_caam_read32(baseaddr + CHAVID_LS);

		if (GET_CHAVID_LS_RNGVID(vid) < 4)
			return CAAM_NO_ERROR;
	} else {
		vid = io_caam_read32(baseaddr + RNG_VERSION);

		if (GET_RNG_VERSION_VID(vid) < 4)
			return CAAM_NO_ERROR;
	}

	/* Get the Number of State Handles */
	nb_sh = caam_hal_rng_get_nb_sh(baseaddr);

	/* Read the RNG Status and checks if all channels are instantiatied */
	status = caam_hal_rng_get_sh_status(baseaddr);

	if (status != GENMASK_32(nb_sh - 1, 0))
		return CAAM_NOT_INIT;

	return CAAM_NO_ERROR;
}

uint32_t caam_hal_rng_get_nb_sh(vaddr_t baseaddr)
{
	uint32_t reg = 0;

	reg = io_caam_read32(baseaddr + CTPR_MS);

	return GET_CTPR_MS_RNG_I(reg);
}

uint32_t caam_hal_rng_get_sh_status(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + RNG_STA) & (RNG_STA_IF1 | RNG_STA_IF0);
}

bool caam_hal_rng_key_loaded(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + RNG_STA) & RNG_STA_SKVN;
}

enum caam_status caam_hal_rng_kick(vaddr_t baseaddr, uint32_t inc_delay)
{
	uint32_t val = 0;
	uint32_t ent_delay = TRNG_SDCTL_ENT_DLY_MIN + inc_delay;

	if (ent_delay > TRNG_SDCTL_ENT_DLY_MAX)
		return CAAM_OUT_OF_BOUND;

	/*
	 * Switch RNG in program mode
	 * Setting both RTMCTL:PRGM and RTMCTL:TRNG_ACC causes TRNG to
	 * properly invalidate the entropy in the entropy register and
	 * force re-generation
	 */
	io_setbits32(baseaddr + TRNG_MCTL, TRNG_MCTL_PRGM | TRNG_MCTL_ACC);

	/*
	 * Configure the RNG Entropy Delay
	 * Performance-wise, it does not make sense to
	 * set the delay to a value that is lower
	 * than the last one that worked (i.e. the state handles
	 * were instantiated correctly). Thus, instead of wasting
	 * time trying to set the values controlling the sample
	 * frequency, the function simply returns.
	 */
	val = io_caam_read32(baseaddr + TRNG_SDCTL);
	val = GET_TRNG_SDCTL_ENT_DLY(val);

	if (ent_delay < val) {
		/*
		 * In this case do the programmation anyway because on some
		 * device the other registers value can be wrong.
		 */
		ent_delay = val;
	}

	io_caam_write32(baseaddr + TRNG_SDCTL, TRNG_SDCTL_ENT_DLY(ent_delay) |
					       TRNG_SDCTL_SAMP_SIZE(512));

	/* min. freq. count, equal to 1/4 of the entropy sample length */
	io_caam_write32(baseaddr + TRNG_FRQMIN, ent_delay >> 2);

	/* max. freq. count, equal to 16 times the entropy sample length */
	io_caam_write32(baseaddr + TRNG_FRQMAX, ent_delay << 4);

	io_caam_write32(baseaddr + TRNG_RTSCMISC,
			TRNG_RTSCMISC_RTY_CNT(2) | TRNG_RTSCMISC_LRUN_MAX(32));
	io_caam_write32(baseaddr + TRNG_RTPKRRNG, TRNG_RTPKRRNG_PKR_RNG(570));
	io_caam_write32(baseaddr + TRNG_RTPKRMAX, TRNG_RTPKRMAX_PKR_MAX(1600));
	io_caam_write32(baseaddr + TRNG_RTSCML,
			TRNG_RTSCML_MONO_RNG(122) | TRNG_RTSCML_MONO_MAX(317));
	io_caam_write32(baseaddr + TRNG_RTSCR1L,
			TRNG_RTSCR1L_RUN1_RNG(80) | TRNG_RTSCR1L_RUN1_MAX(107));
	io_caam_write32(baseaddr + TRNG_RTSCR2L,
			TRNG_RTSCR2L_RUN2_RNG(57) | TRNG_RTSCR2L_RUN2_MAX(62));
	io_caam_write32(baseaddr + TRNG_RTSCR3L,
			TRNG_RTSCR3L_RUN3_RNG(39) | TRNG_RTSCR3L_RUN3_MAX(39));
	io_caam_write32(baseaddr + TRNG_RTSCR4L,
			TRNG_RTSCR4L_RUN4_RNG(27) | TRNG_RTSCR4L_RUN4_MAX(26));
	io_caam_write32(baseaddr + TRNG_RTSCR5L,
			TRNG_RTSCR5L_RUN5_RNG(19) | TRNG_RTSCR5L_RUN5_MAX(18));
	io_caam_write32(baseaddr + TRNG_RTSCR6PL,
			TRNG_RTSCR5L_RUN5_RNG(18) | TRNG_RTSCR5L_RUN5_MAX(17));

	val = io_caam_read32(baseaddr + TRNG_MCTL);
	/*
	 * Select raw sampling in both entropy shifter
	 * and statistical checker
	 */
	val &= ~BM_TRNG_MCTL_SAMP_MODE;
	val |= TRNG_MCTL_SAMP_MODE_RAW_ES_SC;
	/* Put RNG4 into run mode with handling CAAM/RNG4-TRNG Errata */
	val &= ~(TRNG_MCTL_PRGM | TRNG_MCTL_ACC);
	io_caam_write32(baseaddr + TRNG_MCTL, val);

	/*
	 * Clear the ERR bit in RTMCTL if set. The TRNG error can occur when
	 * the RNG clock is not within 1/2x to 8x the system clock.
	 * This error is possible if ROM code does not initialize the system
	 * PLLs immediately after PoR.
	 */
	io_setbits32(baseaddr + TRNG_MCTL, TRNG_MCTL_ERR);

	return CAAM_NO_ERROR;
}
