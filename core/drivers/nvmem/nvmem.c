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
