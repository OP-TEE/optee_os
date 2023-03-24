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
#include <matrix.h>
#include <sama5d2.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <trace.h>

static uint8_t *hw_unique_key;
static uint8_t *die_id;
static size_t die_id_len;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	if (!hw_unique_key)
		return TEE_ERROR_NO_DATA;

	memcpy(hwkey->data, hw_unique_key, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}

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

static TEE_Result nvmem_otp_read_hw_unique_key(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nvmem_cell *cell = NULL;
	uint8_t *data = NULL;
	size_t len = 0;

	res = nvmem_get_cell_by_name(fdt, node, "hw_unique_key", &cell);
	if (res)
		return res;

	res = nvmem_cell_read(cell, &data, &len);
	if (res)
		goto out_free_cell;

	if (len != HW_UNIQUE_KEY_LENGTH) {
		res = TEE_ERROR_GENERIC;
		free(data);
		goto out_free_cell;
	}
	hw_unique_key = data;

out_free_cell:
	nvmem_put_cell(cell);

	return res;
}

static TEE_Result nvmem_otp_read_die_id(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nvmem_cell *cell = NULL;
	uint8_t *data = NULL;

	res = nvmem_get_cell_by_name(fdt, node, "die_id", &cell);
	if (res)
		return res;

	res = nvmem_cell_read(cell, &data, &die_id_len);
	if (!res)
		die_id = data;

	nvmem_put_cell(cell);

	return res;
}

static TEE_Result nvmem_otp_key_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = nvmem_otp_read_hw_unique_key(fdt, node);
	if (res)
		return res;

	res = nvmem_otp_read_die_id(fdt, node);
	if (res) {
		free(hw_unique_key);
		hw_unique_key = NULL;
	}

	return res;
}

static const struct dt_device_match nvmem_otp_key_match_table[] = {
	{ .compatible = "optee,nvmem-otp-key" },
	{ }
};

DEFINE_DT_DRIVER(nvmem_otp_key_dt_driver) = {
	.name = "nvmem_otp_key",
	.type = DT_DRIVER_NOTYPE,
	.match_table = nvmem_otp_key_match_table,
	.probe = nvmem_otp_key_probe,
};
