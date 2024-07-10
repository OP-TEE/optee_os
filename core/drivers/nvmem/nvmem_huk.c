// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Microchip
 */

#include <drivers/nvmem.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/huk_subkey.h>
#include <kernel/tee_common_otp.h>
#include <libfdt.h>
#include <malloc.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

static uint8_t *huk;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	if (!huk) {
		EMSG("no HUK");
		return TEE_ERROR_GENERIC;
	}

	memcpy(hwkey->data, huk, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}

static TEE_Result nvmem_huk_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nvmem_cell *cell = NULL;
	uint8_t *data = NULL;

	res = nvmem_get_cell_by_name(fdt, node, "hw_unique_key", &cell);
	if (res)
		return res;

	if (cell->len < HW_UNIQUE_KEY_LENGTH) {
		EMSG("cell %s is too small", fdt_get_name(fdt, node, NULL));
		nvmem_put_cell(cell);
		return TEE_ERROR_GENERIC;
	}

	if (cell->len > HW_UNIQUE_KEY_LENGTH)
		IMSG("nvmem_huk: HUK truncated from %zu to %u bytes",
		     cell->len, HW_UNIQUE_KEY_LENGTH);

	res = nvmem_cell_malloc_and_read(cell, &data);
	if (!res)
		huk = data;

	nvmem_put_cell(cell);

	return res;
}

static const struct dt_device_match nvmem_huk_match_table[] = {
	{ .compatible = "optee,nvmem-huk" },
	{ }
};

DEFINE_DT_DRIVER(nvmem_huk_dt_driver) = {
	.name = "nvmem_huk",
	.type = DT_DRIVER_NVMEM,
	.match_table = nvmem_huk_match_table,
	.probe = nvmem_huk_probe,
};
