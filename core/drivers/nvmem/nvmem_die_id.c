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

static uint8_t *die_id;
static size_t die_id_len;

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	if (!die_id) {
		if (huk_subkey_derive(HUK_SUBKEY_DIE_ID, NULL, 0, buffer, len))
			return -1;
		return 0;
	}

	memcpy(buffer, die_id, MIN(die_id_len, len));

	return 0;
}

static TEE_Result nvmem_die_id_probe(const void *fdt, int node,
				     const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nvmem_cell *cell = NULL;
	uint8_t *data = NULL;

	res = nvmem_get_cell_by_name(fdt, node, "die_id", &cell);
	if (res)
		return res;

	res = nvmem_cell_malloc_and_read(cell, &data);
	if (!res)
		die_id = data;

	nvmem_put_cell(cell);

	return res;
}

static const struct dt_device_match nvmem_die_id_match_table[] = {
	{ .compatible = "optee,nvmem-die-id" },
	{ }
};

DEFINE_DT_DRIVER(nvmem_die_id_dt_driver) = {
	.name = "nvmem_die_id_key",
	.type = DT_DRIVER_NVMEM,
	.match_table = nvmem_die_id_match_table,
	.probe = nvmem_die_id_probe,
};
