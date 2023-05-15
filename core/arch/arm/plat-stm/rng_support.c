// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
 */

#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>

#include "rng_support.h"

/* Address of the register to read in the RNG IP */
#define RNG_VAL_OFFSET             0x24
#define RNG_STATUS_OFFSET          0x20

#define RNG_STATUS_ERR0		BIT32(0)
#define RNG_STATUS_ERR1		BIT32(1)
#define RNG_STATUS_FULL		BIT32(5)

static vaddr_t rng_base(void)
{
	static void *va;

	if (cpu_mmu_enabled()) {
		if (!va)
			va = phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC, RNG_SIZE);
		return (vaddr_t)va;
	}
	return RNG_BASE;
}

static inline int hwrng_waithost_fifo_full(void)
{
	uint32_t status;

	do {
		status = io_read32(rng_base() + RNG_STATUS_OFFSET);
	} while (!(status & RNG_STATUS_FULL));

	if (status & (RNG_STATUS_ERR0 | RNG_STATUS_ERR1))
		return 1;

	return 0;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
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
	static int pos;

	static int nbcall;  /* debug purpose - 0 is the initial value*/

	volatile uint32_t tmpval[_LOCAL_FIFO_SIZE/2];
	int i;

	uint8_t *buffer = buf;
	size_t buffer_pos = 0;

	nbcall++;

	while (buffer_pos < len) {
		/* Refill our FIFO */
		if (pos == 0) {
			if (hwrng_waithost_fifo_full())
				return TEE_ERROR_GENERIC;

			/*
			 * Read the FIFO according to the number of
			 * expected elements
			 */
			for (i = 0; i < _LOCAL_FIFO_SIZE / 2; i++)
				tmpval[i] = io_read32(rng_base() +
						      RNG_VAL_OFFSET) & 0xFFFF;

			/* Update the local SW fifo for next request */
			pos = 0;
			for (i = 0; i < _LOCAL_FIFO_SIZE / 2; i++) {
				lfifo[pos] = tmpval[i] & 0xFF;
				pos++;
				lfifo[pos] = (tmpval[i] >> 8) & 0xFF;
				pos++;
			}
			pos = 0;
		}

		buffer[buffer_pos++] = lfifo[pos++];
		if (pos == _LOCAL_FIFO_SIZE)
			pos = 0;
	}

	return TEE_SUCCESS;
}
