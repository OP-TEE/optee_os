// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Microchip
 */

#include <drivers/nvmem.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/huk_subkey.h>
#include <kernel/tee_common_otp.h>
#include <malloc.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

static struct nvmem_cell *huk_cell;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *huk = NULL;
	size_t len = 0;

	res = nvmem_cell_malloc_and_read(huk_cell, &huk);
	if (res)
		goto out_free_cell;

	if (len != HW_UNIQUE_KEY_LENGTH) {
		res = TEE_ERROR_GENERIC;
		goto out_free_cell;
	}

	memcpy(hwkey->data, huk, HW_UNIQUE_KEY_LENGTH);

out_free_cell:
	nvmem_put_cell(huk_cell);

	return res;
}

static TEE_Result nvmem_huk_get_cell(const void *fdt, int node)
{
	return nvmem_get_cell_by_name(fdt, node, "hw_unique_key", &huk_cell);
}

static TEE_Result nvmem_huk_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	return nvmem_huk_get_cell(fdt, node);
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
