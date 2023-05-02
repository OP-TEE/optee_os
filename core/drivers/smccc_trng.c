// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <kernel/thread_arch.h>
#include <rng_support.h>
#include <sm/std_smc.h>
#include <stdbool.h>
#include <string.h>
#include <util.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

/*
 * Arm SMCCC TRNG firmware interface specification:
 * https://developer.arm.com/documentation/den0098/
 */
#define ARM_SMCCC_TRNG_VERSION		0x84000050
#define ARM_SMCCC_TRNG_FEATURES		0x84000051
#define ARM_SMCCC_TRNG_GET_UUID		0x84000052
#define ARM_SMCCC_TRNG_RND_32		0x84000053
#define ARM_SMCCC_TRNG_RND_64		0xc4000053

#define ARM_SMCCC_RET_TRNG_SUCCESS		U(0)
#define ARM_SMCCC_RET_TRNG_NOT_SUPPORTED	((unsigned long)-1)
#define ARM_SMCCC_RET_TRNG_INVALID_PARAMETER	((unsigned long)-2)
#define ARM_SMCCC_RET_TRNG_NO_ENTROPY		((unsigned long)-3)

#define TRNG_MAJOR_MASK		GENMASK_32(30, 16)
#define TRNG_MAJOR_SHIFT	16
#define TRNG_MINOR_MASK		GENMASK_32(15, 0)
#define TRNG_MINOR_SHIFT	0
#define TRNG_MAKE_VERSION(major, minor)	\
	((SHIFT_U32(major, TRNG_MAJOR_SHIFT) & TRNG_MAJOR_MASK) | \
	 (SHIFT_U32(minor, TRNG_MINOR_SHIFT) & TRNG_MINOR_MASK))

#define TRNG_VERSION_1_0	TRNG_MAKE_VERSION(1, 0)

#define TRNG_MAX_RND_64		(192 / 8)
#define TRNG_MAX_RND_32		(96 / 8)

/* Function ID discovered for getting random bytes or 0 if not supported */
static uint32_t trng_rnd_fid;

static bool smccc_trng_is_supported(void)
{
	struct thread_smc_args args = { };
	static bool inited;

	if (inited)
		return trng_rnd_fid != 0;

	inited = true;

	/*
	 * TRNG ABI requires caller to check that Arm SMCCC version is
	 * larger or equal to v1.1
	 */
	args.a0 = ARM_SMCCC_VERSION;
	thread_smccc(&args);
	if (args.a0 & BIT32(31) || args.a0 < SMCCC_V_1_1)
		return false;

	/*
	 * Check TRNG version, if successful we're guaranteed to have at least
	 * the ARM_SMCCC_TRNG_FEATURES fid.
	 */
	args.a0 = ARM_SMCCC_TRNG_VERSION;
	thread_smccc(&args);
	if (args.a0 & BIT32(31) || args.a0 < TRNG_VERSION_1_0)
		return false;

#ifdef ARM64
	args.a0 = ARM_SMCCC_TRNG_FEATURES;
	args.a1 = ARM_SMCCC_TRNG_RND_64;
	thread_smccc(&args);
	if (args.a0 == ARM_SMCCC_RET_SUCCESS) {
		trng_rnd_fid = ARM_SMCCC_TRNG_RND_64;
		return true;
	}
#endif

	args.a0 = ARM_SMCCC_TRNG_FEATURES;
	args.a1 = ARM_SMCCC_TRNG_RND_32;
	thread_smccc(&args);
	if (args.a0 == ARM_SMCCC_RET_TRNG_SUCCESS) {
		trng_rnd_fid = ARM_SMCCC_TRNG_RND_32;
		return true;
	}

	return false;
}

static void read_bytes(unsigned long val, size_t byte_count, uint8_t **buf,
		       size_t *rem)
{
	size_t count = MIN(byte_count, *rem);
	size_t n = 0;

	for (n = 0; n < count; n++)
		(*buf)[n] = val >> (n * 8);

	*buf += count;
	*rem -= count;
}

static void read_samples(struct thread_smc_args *args, uint8_t *buf, size_t len)
{
	uint8_t *ptr = buf;
	size_t rem = len;
	size_t byte_count = 4;

#ifdef ARM64
	if (trng_rnd_fid == ARM_SMCCC_TRNG_RND_64)
		byte_count = 8;
#endif

	read_bytes(args->a3, byte_count, &ptr, &rem);
	read_bytes(args->a2, byte_count, &ptr, &rem);
	read_bytes(args->a1, byte_count, &ptr, &rem);
}

static TEE_Result __maybe_unused smccc_trng_read(void *buf, size_t len)
{
	struct thread_smc_args args = { };
	uint8_t *ptr = buf;
	size_t rem = len;
	size_t max_burst = 0;

	if (!smccc_trng_is_supported())
		return TEE_ERROR_NOT_SUPPORTED;

	if (trng_rnd_fid == ARM_SMCCC_TRNG_RND_64)
		max_burst = TRNG_MAX_RND_64;
	else
		max_burst = TRNG_MAX_RND_32;

	while (rem) {
		size_t burst = MIN(rem, max_burst);

		args.a0 = trng_rnd_fid;
		args.a1 = burst * 8;

		thread_smccc(&args);

		switch (args.a0) {
		case ARM_SMCCC_RET_TRNG_SUCCESS:
			read_samples(&args, ptr, burst);
			rem -= burst;
			ptr += burst;
			break;
		case ARM_SMCCC_RET_TRNG_NO_ENTROPY:
			break;
		default:
			return TEE_ERROR_GENERIC;
		}
	}

	return TEE_SUCCESS;
}

static void __maybe_unused smccc_trng_print_info(void)
{
	struct thread_smc_args args = { };
	unsigned int __maybe_unused major = 0;
	unsigned int __maybe_unused minor = 0;

	if (!IS_ENABLED(CFG_TEE_CORE_DEBUG))
		return;

	args.a0 = ARM_SMCCC_TRNG_VERSION;
	thread_smccc(&args);
	assert((args.a0 & BIT32(31)) == 0);
	major = (args.a0 & TRNG_MAJOR_MASK) >> TRNG_MAJOR_SHIFT;
	minor = (args.a0 & TRNG_MINOR_MASK) >> TRNG_MINOR_SHIFT;

	args.a0 = ARM_SMCCC_TRNG_GET_UUID;
	thread_smccc(&args);
	assert(args.a0 != ARM_SMCCC_RET_TRNG_NOT_SUPPORTED);

	DMSG("SMCCC TRNG v%u.%u, UUID %08lx-%04lx-%04lx-%04lx-%04lx%08lx\n",
	     major, minor, (unsigned long)args.a0, (unsigned long)args.a1 >> 16,
	     (unsigned long)args.a1 & GENMASK_32(16, 0),
	     (unsigned long)args.a2 >> 16,
	     (unsigned long)args.a2 & GENMASK_32(16, 0),
	     (unsigned long)args.a3);
}

void plat_rng_init(void)
{
	if (!smccc_trng_is_supported())
		panic("SMCCC TRNG not supported");

	smccc_trng_print_info();

	if (IS_ENABLED(CFG_WITH_SOFTWARE_PRNG)) {
		/* If CFG_WITH_SOFTWARE_PRNG is enabled, seed PRNG with TRNG */
		uint8_t seed[32] = { 0 };

		if (smccc_trng_read(seed, sizeof(seed)))
			panic("SMCCC TRNG not supported");

		if (crypto_rng_init(seed, sizeof(seed)))
			panic();
	}
}

/* If CFG_WITH_SOFTWARE_PRNG is disabled, TRNG is our HW RNG */
#ifndef CFG_WITH_SOFTWARE_PRNG
TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return smccc_trng_read(buf, len);
}
#endif
