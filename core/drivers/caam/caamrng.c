// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */
#include <io.h>

#include "intern.h"
#include "rng_regs.h"

void kick_trng(vaddr_t ctrl_base, uint32_t ent_delay)
{
	uint32_t val;

	/* Put RNG in program mode */
	io_mask32(ctrl_base + TRNG_MCTL, BM_TRNG_MCTL_PRGM, BM_TRNG_MCTL_PRGM);

	/* Configure the RNG Entropy Delay
	 * Performance-wise, it does not make sense to
	 * set the delay to a value that is lower
	 * than the last one that worked (i.e. the state handles
	 * were instantiated properly. Thus, instead of wasting
	 * time trying to set the values controlling the sample
	 * frequency, the function simply returns.
	 */
	val = read32(ctrl_base + TRNG_SDCTL);
	val &= BM_TRNG_SDCTL_ENT_DLY;
	val >>= BS_TRNG_SDCTL_ENT_DLY;

	if (ent_delay <= val) {
		/* Put RNG4 into run mode */
		io_mask32(ctrl_base + TRNG_MCTL,
			~BM_TRNG_MCTL_PRGM, BM_TRNG_MCTL_PRGM);
		return;
	}

	val = read32(ctrl_base + TRNG_SDCTL);
	val &= ~BM_TRNG_SDCTL_ENT_DLY;
	val |= ent_delay << BS_TRNG_SDCTL_ENT_DLY;
	write32(val, ctrl_base + TRNG_SDCTL);

	/* min. freq. count, equal to 1/4 of the entropy sample length */
	write32(ent_delay >> 2, ctrl_base + TRNG_FRQMIN);

	/* max. freq. count, equal to 16 times the entropy sample length */
	write32(ent_delay << 4, ctrl_base + TRNG_FRQMAX);

	val = read32(ctrl_base + TRNG_MCTL);
	/*
	 * Select raw sampling in both entropy shifter
	 * and statistical checker
	 */
	val &= ~BM_TRNG_MCTL_SAMP_MODE;
	val |= TRNG_MCTL_SAMP_MODE_RAW_ES_SC;
	/* Put RNG4 into run mode */
	val &= ~BM_TRNG_MCTL_PRGM;
	write32(val, ctrl_base + TRNG_MCTL);
}


