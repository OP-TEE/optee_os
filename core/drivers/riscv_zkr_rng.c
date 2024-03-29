// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <riscv.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>

#define OPST_BIST 0b00
#define OPST_WAIT 0b01
#define OPST_ES16 0b10
#define OPST_DEAD 0b11

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *ptr = buf;
	uint32_t val = 0;

	while (len > 0) {
		/*
		 * The seed register must be accessed using CSR read-write
		 * instructions. The write operation is ignored and serves
		 * to indicate polling and flushing.
		 */
		val = swap_csr(CSR_SEED, val);

		switch (val >> 30) {
		case OPST_BIST:
		case OPST_WAIT:
			continue;
		case OPST_ES16:
			*ptr++ = val & 0xff;
			len--;
			if (len > 0) {
				*ptr++ = val >> 8;
				len--;
			}
			break;
		case OPST_DEAD:
			/* Unrecoverable self-test error */
			return TEE_ERROR_BAD_STATE;
		default:
			break; /* can't happen */
		}
	}

	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
	if (!riscv_detect_csr_seed())
		panic("RISC-V Zkr is not supported or unavailable in S-mode");
}
