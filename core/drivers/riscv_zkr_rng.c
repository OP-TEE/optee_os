// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <crypto/crypto.h>
#include <encoding.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <riscv.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>

#define RNG_TIMEOUT_US	1000000

static bool __must_check seed_get_random_u16(uint16_t *val)
{
	uint64_t timeout = timeout_init_us(RNG_TIMEOUT_US);
	uint32_t seed = 0;
	uint32_t opst = 0;

	do {
		/*
		 * The seed register must be accessed using CSR
		 * read-write instructions. The write operation
		 * is ignored and serves to indicate polling and
		 * flushing.
		 */
		seed = swap_csr(CSR_SEED, 0);
		opst = seed & SEED_OPST;

		switch (opst) {
		case SEED_OPST_ES16:
			*val = seed & SEED_ENTROPY;
			return true;
		case SEED_OPST_DEAD:
			/* Unrecoverable self-test error */
			return false;
		case SEED_OPST_BIST:
		case SEED_OPST_WAIT:
		default:
			riscv_cpu_pause();
		}
	} while (!timeout_elapsed(timeout));

	/* Consider timeout case due to normal world scheduler */
	seed = swap_csr(CSR_SEED, 0);
	if ((seed & SEED_OPST) == SEED_OPST_ES16) {
		*val = seed & SEED_ENTROPY;
		return true;
	}

	EMSG("Failed to produce a sufficient amount of entropy");

	return false;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *ptr = buf;
	uint16_t seed = 0;

	while (len > 0) {
		if (!seed_get_random_u16(&seed))
			return TEE_ERROR_ACCESS_DENIED;
		*ptr++ = seed & 0xff;
		len--;
		if (len > 0) {
			*ptr++ = seed >> 8;
			len--;
		}
	}

	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
	if (!riscv_detect_csr_seed())
		panic("RISC-V Zkr is not supported or unavailable in S-mode");
}
