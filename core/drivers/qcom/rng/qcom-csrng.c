// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>

#define QCOM_RNG_REG_SIZE			0x1000

#define QCOM_RNG_DATA_OUT			0x0
#define QCOM_RNG_STATUS				0x4
#define QCOM_RNG_STATUS_DATA_AVAIL_BMSK	0x1

#define QCOM_RNG_TIMEOUT_US			1000000

static struct {
	paddr_t pa;
	vaddr_t va;
} rng = {
	.pa = QCOM_RNG_REG_BASE,
};

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *out = buf;
	uint32_t val = 0;
	uint64_t to = 0;

	if (!rng.va)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!out || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	to = timeout_init_us(QCOM_RNG_TIMEOUT_US);
	while (len) {
		if (!(io_read32(rng.va + QCOM_RNG_STATUS) &
		      QCOM_RNG_STATUS_DATA_AVAIL_BMSK)) {
			if (timeout_elapsed(to))
				return TEE_ERROR_BUSY;
			continue;
		}

		while ((val = io_read32(rng.va + QCOM_RNG_DATA_OUT)) == 0) {
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

static TEE_Result qcom_csrng_init(void)
{
	rng.va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC, rng.pa,
					       QCOM_RNG_REG_SIZE);
	if (!rng.va)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

early_init(qcom_csrng_init);
