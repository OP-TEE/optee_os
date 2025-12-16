// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>

#define SEC_PRNG_REG_SIZE			0x1000

#define SEC_PRNG_DATA_OUT			0x0
#define SEC_PRNG_STATUS				0x4
#define SEC_PRNG_STATUS_DATA_AVAIL_BMSK		0x1

static struct {
	paddr_t pa;
	vaddr_t va;
} prng = {
	.pa = SEC_PRNG_REG_BASE,
};

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *out = buf;
	uint32_t val;

	if (!prng.va)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!out || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	while (len) {
		if (!(io_read32(prng.va + SEC_PRNG_STATUS) &
		      SEC_PRNG_STATUS_DATA_AVAIL_BMSK))
			continue;

		while ((val = io_read32(prng.va + SEC_PRNG_DATA_OUT)) == 0)
			;

		for (size_t i = 0; i < sizeof(val) && len; i++) {
			*out++ = (uint8_t)(val >> (i * 8));
			len--;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result qcom_prng_init(void)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, prng.pa, SEC_PRNG_REG_SIZE))
		return TEE_ERROR_GENERIC;

	prng.va = (vaddr_t)phys_to_virt_io(prng.pa, SEC_PRNG_REG_SIZE);
	if (!prng.va)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

early_init(qcom_prng_init);
