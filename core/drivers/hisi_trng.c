// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2023 HiSilicon Limited. */

#include <initcall.h>
#include <io.h>
#include <kernel/spinlock.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <rng_support.h>
#include <drivers/device_dt.h>
#include <kernel/delay.h>
#include <string.h>

#define HTRNG_RANDATA_REG 0xF0
#define HTRNG_BYTES 4U

#define POLL_PERIOD 10
#define POLL_TIMEOUT 1000

struct hisi_trng {
	uintptr_t base;
	uint32_t size;
};

static unsigned int trng_lock = SPINLOCK_UNLOCK;
static struct hisi_trng *trng_dev;

static TEE_Result trng_read(uint32_t *val)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&trng_lock);
	if (IO_READ32_POLL_TIMEOUT(trng_dev->base + HTRNG_RANDATA_REG,
				   *val, *val, POLL_PERIOD, POLL_TIMEOUT)) {
		EMSG("Hardware busy");
		ret = TEE_ERROR_BUSY;
	}
	cpu_spin_unlock_xrestore(&trng_lock, exceptions);

	return ret;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t current_len = 0;
	uint32_t val = 0;
	size_t size = 0;

	if (!trng_dev) {
		EMSG("No valid TRNG device");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (!buf || !len) {
		EMSG("Invalid input parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	while (current_len < len) {
		ret = trng_read(&val);
		if (ret)
			return TEE_ERROR_BUSY;

		size = MIN(HTRNG_BYTES, len - current_len);
		memcpy((uint8_t *)buf + current_len, &val, size);
		current_len += size;
	}

	return TEE_SUCCESS;
}

static TEE_Result trng_init(void)
{
	const char *dt_dev_match = "hisi-trng";
	TEE_Result ret = TEE_ERROR_GENERIC;

	IMSG("TRNG driver init start");
	trng_dev = (struct hisi_trng *)calloc(1, sizeof(struct hisi_trng));
	if (!trng_dev) {
		EMSG("Fail to calloc trng device");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ret = set_device_info_by_dt(&trng_dev->base, &trng_dev->size, dt_dev_match);
	if (ret) {
		free(trng_dev);
		trng_dev = NULL;
		return ret;
	}

	trng_dev->base = (vaddr_t)phys_to_virt_io(trng_dev->base,
						  trng_dev->size);
	if (!trng_dev->base) {
		EMSG("Fail to get trng io_base");
		free(trng_dev);
		trng_dev = NULL;
		return TEE_ERROR_ACCESS_DENIED;
	}

	IMSG("TRNG driver init done");

	return TEE_SUCCESS;
}

early_init(trng_init);
