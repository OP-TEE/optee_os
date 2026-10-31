// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>

#define QCOM_RNG_REG_SIZE			0x1000

#define QCOM_RNG_DATA_OUT			0x0
#define QCOM_RNG_STATUS				0x4
#define QCOM_RNG_STATUS_DATA_AVAIL_BMSK	0x1

#define QCOM_RNG_TIMEOUT_US			1000000

static struct mutex rng_lock = MUTEX_INITIALIZER;

static struct io_pa_va rng = {
	.pa = QCOM_RNG_REG_BASE,
};

/* No lock, so it can be used before the MMU is enabled (registers via PA) */
TEE_Result hw_get_random_bytes_nolock(void *buf, size_t len)
{
	uint8_t *out = buf;
	vaddr_t base = 0;
	uint32_t val = 0;
	uint64_t to = 0;

	if (!out || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	base = io_pa_or_va_secure(&rng, QCOM_RNG_REG_SIZE);
	to = timeout_init_us(QCOM_RNG_TIMEOUT_US);
	while (len) {
		if (!(io_read32(base + QCOM_RNG_STATUS) &
		      QCOM_RNG_STATUS_DATA_AVAIL_BMSK)) {
			if (timeout_elapsed(to))
				return TEE_ERROR_BUSY;
			continue;
		}

		while ((val = io_read32(base + QCOM_RNG_DATA_OUT)) == 0) {
			if (timeout_elapsed(to))
				return TEE_ERROR_BUSY;
		}

		for (size_t i = 0; i < sizeof(val) && len; i++) {
			*out++ = (uint8_t)(val >> (i * 8));
			len--;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	mutex_lock(&rng_lock);
	res = hw_get_random_bytes_nolock(buf, len);
	mutex_unlock(&rng_lock);

	return res;
}

/* Called before the MMU is enabled */
unsigned long plat_get_aslr_seed(void)
{
	unsigned long seed = 0;

	if (hw_get_random_bytes_nolock(&seed, sizeof(seed)))
		panic("Failed to get the ASLR seed");

	return seed;
}

static TEE_Result qcom_csrng_init(void)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, rng.pa, QCOM_RNG_REG_SIZE))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

early_init(qcom_csrng_init);
