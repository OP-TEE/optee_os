// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Microchip
 */

#include <drivers/nvmem.h>
#include <io.h>
#include <kernel/dt_driver.h>
#include <malloc.h>
#include <matrix.h>
#include <platform_config.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define ATMEL_SFC_KR		0x0
#define ATMEL_SFC_SR		0x1C
#define ATMEL_SFC_SR_PGMC	BIT(0)
#define ATMEL_SFC_SR_PGMF	BIT(1)
#define ATMEL_SFC_DR		0x20

#define ATMEL_SFC_CELLS_32	17
#define ATMEL_SFC_CELLS_8	(ATMEL_SFC_CELLS_32 * sizeof(uint32_t))

struct atmel_sfc {
	vaddr_t base;
	uint8_t fuses[ATMEL_SFC_CELLS_8];
};

static TEE_Result atmel_sfc_read_cell(struct nvmem_cell *cell, uint8_t *data)
{
	struct atmel_sfc *atmel_sfc = cell->drv_data;

	memcpy(data, &atmel_sfc->fuses[cell->offset], cell->len);

	return TEE_SUCCESS;
}

static void atmel_sfc_put_cell(struct nvmem_cell *cell)
{
	free(cell);
}

static const struct nvmem_ops atmel_sfc_nvmem_ops = {
	.read_cell = atmel_sfc_read_cell,
	.put_cell = atmel_sfc_put_cell,
};

static TEE_Result atmel_sfc_dt_get(struct dt_pargs *args,
				   void *data, struct nvmem_cell **out_cell)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nvmem_cell *cell = NULL;

	/* Freed from atmel_sfc_put_cell() */
	cell = calloc(1, sizeof(*cell));
	if (!cell)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = nvmem_cell_parse_dt(args->fdt, args->phandle_node, cell);
	if (res)
		goto out_free;

	if (cell->offset + cell->len > ATMEL_SFC_CELLS_8) {
		res = TEE_ERROR_GENERIC;
		goto out_free;
	}

	cell->ops = &atmel_sfc_nvmem_ops;
	cell->drv_data = data;
	*out_cell = cell;

	return TEE_SUCCESS;

out_free:
	free(cell);

	return res;
}

static void atmel_sfc_read_fuse(struct atmel_sfc *atmel_sfc)
{
	size_t i = 0;
	uint32_t val = 0;

	for (i = 0; i < ATMEL_SFC_CELLS_32; i++) {
		val = io_read32(atmel_sfc->base + ATMEL_SFC_DR + i * 4);
		memcpy(&atmel_sfc->fuses[i * 4], &val, sizeof(val));
	}
}

static TEE_Result atmel_sfc_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	vaddr_t base = 0;
	size_t size = 0;
	struct atmel_sfc *atmel_sfc = NULL;

	if (fdt_get_status(fdt, node) != DT_STATUS_OK_SEC)
		return TEE_ERROR_NODE_DISABLED;

	matrix_configure_periph_secure(AT91C_ID_SFC);

	if (dt_map_dev(fdt, node, &base, &size, DT_MAP_AUTO) < 0)
		return TEE_ERROR_GENERIC;

	atmel_sfc = calloc(1, sizeof(*atmel_sfc));
	if (!atmel_sfc)
		return TEE_ERROR_OUT_OF_MEMORY;

	atmel_sfc->base = base;

	atmel_sfc_read_fuse(atmel_sfc);

	return nvmem_register_provider(fdt, node, atmel_sfc_dt_get, atmel_sfc);
}

static const struct dt_device_match atmel_sfc_match_table[] = {
	{ .compatible = "atmel,sama5d2-sfc" },
	{ }
};

DEFINE_DT_DRIVER(atmel_sfc_dt_driver) = {
	.name = "atmel_sfc",
	.type = DT_DRIVER_NVMEM,
	.match_table = atmel_sfc_match_table,
	.probe = atmel_sfc_probe,
};
