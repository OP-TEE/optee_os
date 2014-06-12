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

#include <stdlib.h>
#include <rng_support.h>
#include <kernel/tee_core_trace.h>

/* Use the RNG of the HW on this platform */
#define USE_RNG_HW

#define USE_FULLY_RNG_HW_IMP 0
#define USE_SW_DELAY         0

/*
 * if a HW issue is detected, infinite loop is started until valid data are
 * available.
 * - User-side timeout is expected to detect the issue.
 * else error is logged and 0x00 is returned
 */
#define USE_USER_TIMEOUT     1

#ifdef USE_RNG_HW

/*
 * Base address of the RNG on Orly-2, taken from document
 *      http://wave.st.com/chd/SOC_HW_Design/default.aspx
 *          SOC HW Design > ORLY > ORLY2_cut1.0 > SoC_Reg_Spec
 *              top_mpe42.xls
 */
#define RNG_BASE_ADDRESS      0xFEE80000

/* Address of the register to read in the RNG IP */
#define RNG_VAL             (RNG_BASE_ADDRESS + 0x24)
#define RNG_STATUS          (RNG_BASE_ADDRESS + 0x20)

static volatile uint32_t *_p_addr_val    = (uint32_t *)RNG_VAL;
static volatile uint32_t *_p_addr_status = (uint32_t *)RNG_STATUS;

static inline int hwrng_waithost_fifo_full(void)
{
	int res = 0;
	volatile uint32_t status;

	/* Wait HOST FIFO FULL (see rng_fspec_revG_120720.pdf) */
	do {
		status = *_p_addr_status;
	} while ((status & 0x20) != 0x20);

	/* Check STATUS (see rng_fspec_revG_120720.pdf) */
	if ((status & 0x3) != 0) {
		EMSG("generated HW random data are not valid");
		res = -1;
	}

#if (USE_USER_TIMEOUT == 1)
	if (res != 0)
		while (1)
			;
#endif

	return res;
}

uint8_t hw_get_random_byte(void)
#if (USE_FULLY_RNG_HW_IMP == 1)
{
	/*
	 * Only the HW RNG IP is used to generate the value through the
	 * HOST interface.
	 *
	 * @see the document rng_fspec_revG_120720.pdf for details
	 *
	 * - HOST FIFO size = 8x8b (64b)
	 * - LSB (16b) of the RNG_VAL register allows to read 16b
	 * - bit5 of the RNG_STATUS register allows to known if the HOST
	 *   FIFO is full or not.
	 * - bit1,0 of the RNG_STATUS register allows to known if the
	 *   data are valid.
	 *
	 * Main principle:
	 *  For performance reason, a local SW fifo is used to store the
	 *  content of the HOST FIFO (max size = 8bytes). When a random
	 *  value is expected, this SW fifo is used to return a stored value.
	 *  When the local SW fifo is empty, it is filled with the HOST FIFO
	 *  according the following sequence:
	 *
	 *  - wait HOST FIFO full
	 *      o Indicates that max 8-bytes (64b) are available
	 *      o This is mandatory to guarantee that a valid data is
	 *      available. No STATUS bit to indicate that the HOST FIFO
	 *      is empty is provided.
	 *  - check STATUS bits
	 *  - update the local SW fifo with the HOST FIFO
	 *
	 *  This avoid to wait at each iteration that a valid random value is
	 *  available. _LOCAL_FIFO_SIZE indicates the size of the local SW fifo.
	 *
	 */


#define _LOCAL_FIFO_SIZE 8     /* min 2, 4, 6, max 8 */

	static uint8_t lfifo[_LOCAL_FIFO_SIZE];     /* local fifo */
	static int pos = -1;

	static int nbcall;  /* debug purpose - 0 is the initial value*/

	volatile uint32_t tmpval[_LOCAL_FIFO_SIZE/2];
	uint8_t value;
	int i;
	int res;

	nbcall++;

	/* Retrieve data from local fifo */
	if (pos >= 0) {
		pos++;
		value = lfifo[pos];
		if (pos == (_LOCAL_FIFO_SIZE - 1))
			pos = -1;
		return value;
	}

	/* Wait HOST FIFO full */
	res = hwrng_waithost_fifo_full();
	if (res < 0)
		return 0x00;

	/* Read the FIFO according the number of expected element */
	for (i = 0; i < _LOCAL_FIFO_SIZE / 2; i++) {
		tmpval[i] = *_p_addr_val & 0xFFFF;
#if (USE_SW_DELAY == 1)
		/* Wait 0.667 us (fcpu = 600Mhz -> 400 cycles) @see doc */
		volatile int ll = 200;
		while (ll--)
			;
#endif
	}
	/* Update the local SW fifo for next request */
	pos = 0;
	for (i = 0; i < _LOCAL_FIFO_SIZE / 2; i++) {
		lfifo[pos] = tmpval[i] & 0xFF;
		pos++;
		lfifo[pos] = (tmpval[i] >> 8) & 0xFF;
		pos++;
	};

	pos = 0;
	return lfifo[pos];
}
#else  /* USE_FULLY_RNG_HW_IMP != 1 */
{
	/*
	 * The HW RNG IP is used to generate a seed periodically
	 * (MAX_SOFT_RNG) through the HOST interface.
	 *
	 * @see the document rng_fspec_revG_120720.pdf for details
	 *
	 * - Pseudo SW Random generator is used to generate the random
	 *   value.
	 */

	static uint32_t _lcg_state;
	static uint32_t _nb_soft;	/* 0 is the initial value */
	int res;

#define MAX_SOFT_RNG 512

	static const uint32_t _a = 1664525;
	static const uint32_t _c = 1013904223;

	if (_nb_soft == 0) {
		/* Update the seed as a "real" HW random generated number */
		do {
			res = hwrng_waithost_fifo_full();
			if (res < 0)
				return 0x00;
			_lcg_state = *_p_addr_val & 0xFFFF;
			_lcg_state <<= 16;

#if (USE_SW_DELAY == 1)
			/*
			 * Wait 0.667 us (fcpu = 600Mhz -> 400 cycles)
			 * @see doc
			 */
			volatile int ll = 200;
			while (ll--)
				;
#endif
			_lcg_state |= *_p_addr_val & 0xFFFF;
		} while (_lcg_state == 0);
	}
	_nb_soft = (_nb_soft + 1) % MAX_SOFT_RNG;
	_lcg_state = (_a * _lcg_state + _c);

	return (uint8_t) (_lcg_state >> 24);
}
#endif

#else
/* Software version. Comes from the compiler */
uint8_t hw_get_random_byte(void)
{
	static uint8_t value = 1;
	static uint32_t ite;	/* 0 is the initial value */

	ite++;
	srand(ite);
	value = (256 * ((double)rand() / RAND_MAX));
	/* AMSG("SW Random value = 0x%02x", value); */
	return value;
}

#endif

