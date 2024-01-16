// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Microchip
 */

#include <drivers/nvmem.h>
#include <kernel/dt.h>
#include <libfdt.h>

TEE_Result nvmem_cell_parse_dt(const void *fdt, int nodeoffset,
			       struct nvmem_cell *cell)
{
	size_t buf_len = 0;
	paddr_t offset = 0;

	buf_len = fdt_reg_size(fdt, nodeoffset);
	if (buf_len == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_GENERIC;

	offset = fdt_reg_base_address(fdt, nodeoffset);
	if (offset == DT_INFO_INVALID_REG)
		return TEE_ERROR_GENERIC;

	cell->len = buf_len;
	cell->offset = offset;

	return TEE_SUCCESS;
}

TEE_Result nvmem_get_cell_by_name(const void *fdt, int nodeoffset,
				  const char *name, struct nvmem_cell **cell)
{
	int index = 0;

	index = fdt_stringlist_search(fdt, nodeoffset, "nvmem-cell-names",
				      name);
	if (index < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return nvmem_get_cell_by_index(fdt, nodeoffset, index, cell);
}

TEE_Result nvmem_get_cell_by_index(const void *fdt,
				   int nodeoffset,
				   unsigned int index,
				   struct nvmem_cell **out_cell)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *cell = NULL;

	res = dt_driver_device_from_node_idx_prop("nvmem-cells", fdt,
						  nodeoffset, index,
						  DT_DRIVER_NVMEM, &cell);
	if (!res)
		*out_cell = cell;

	return res;
}

TEE_Result nvmem_cell_malloc_and_read(struct nvmem_cell *cell,
				      uint8_t **out_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!cell->ops->read_cell)
		return TEE_ERROR_NOT_SUPPORTED;

	*out_data = malloc(cell->len);
	if (!out_data)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = cell->ops->read_cell(cell, *out_data);
	if (res)
		free(*out_data);

	return res;
}
