/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Microchip
 */

#ifndef __DRIVERS_NVMEM_H
#define __DRIVERS_NVMEM_H

#include <kernel/dt_driver.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

struct nvmem_cell;

/*
 * struct nvmem_ops - Nvmem device driver operations
 * @alloc_read_cell: Allocate @data in the heap and load @len bytes to from an
 * nvmem cell
 * @free_cell: Release resources allocated from nvmem_dt_get_func callback
 * function
 */
struct nvmem_ops {
	TEE_Result (*read_cell)(struct nvmem_cell *cell, uint8_t **data,
				size_t *len);
	void (*free_cell)(struct nvmem_cell *cell);
};

/*
 * struct nvmem_cell - Description of an nvmem cell
 * @offset: Cell byte offset in the NVMEM device
 * @len: Cell byte size
 * @ops: Nvmem device driver operation handlers
 * @drv_data: Nvmem device driver private data
 */
struct nvmem_cell {
	paddr_t offset;
	size_t len;
	const struct nvmem_ops *ops;
	void *drv_data;
};

/*
 * nvmem_dt_get_func - Typedef of function to get an nvmem reference from a DT
 * node
 *
 * @a: Reference to phandle arguments
 * @data: Pointer to data given at nvmem_dt_get_func() call
 * @res: Output result code of the operation:
 *	TEE_SUCCESS in case of success
 *	TEE_ERROR_DEFER_DRIVER_INIT if clock is not initialized
 *	Any TEE_Result compliant code in case of error.
 */
typedef
struct nvmem_cell *(*nvmem_dt_get_func)(struct dt_pargs *a,
					void *data, TEE_Result *res);

#ifdef CFG_DRIVERS_NVMEM
/**
 * nvmem_register_provider() - Register a nvmem controller
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of nvmem cell consumer
 * @get_dt_pinctrl: Callback to match the devicetree nvmem reference with
 * nvmem_cell
 * @data: Data which will be passed to the get_dt_nvmem callback
 * Return a TEE_Result compliant value
 */
static inline TEE_Result nvmem_register_provider(const void *fdt,
						 int nodeoffset,
						 nvmem_dt_get_func get_dt_nvmem,
						 void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)get_dt_nvmem,
					   data, DT_DRIVER_NVMEM);
}

/**
 * nvmem_get_cell_by_name() - Obtain a nvmem cell from its name in the DT node
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of nvmem cell consumer
 * @name: name of the nvmem cell to obtain from the device tree
 * @cell: Pointer filled with the retrieved cell, must be freed after use
   using nvmem_put_cell()
 * Return a TEE_Result compliant value
 */
TEE_Result nvmem_get_cell_by_name(const void *fdt, int nodeoffset,
				  const char *name, struct nvmem_cell **cell);

/**
 * nvmem_get_cell_by_index() - Obtain a nvmem cell from property nvmem-cells
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of nvmem cell consumer
 * @index: Index of the nvmem cell to obtain from device-tree
 * @cell: Pointer filled with the retrieved cell, must be freed after use
 * using nvmem_put_cell()
 * Return a TEE_Result compliant value
 */
static inline TEE_Result nvmem_get_cell_by_index(const void *fdt,
						 int nodeoffset,
						 unsigned int index,
						 struct nvmem_cell **cell)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	*cell = dt_driver_device_from_node_idx_prop("nvmem-cells", fdt,
						    nodeoffset, index,
						    DT_DRIVER_NVMEM, &res);
	return res;
}

/**
 * nvmem_cell_parse_dt() - Parse device-tree information to fill a nvmem cell
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the nvmem cell controller
 * @cell: Pointer to cell that will be filled
 */
TEE_Result nvmem_cell_parse_dt(const void *fdt, int nodeoffset,
			       struct nvmem_cell *cell);

/**
 * nvmem_put_cell() - Free resource allocated from nvmem_get_cell_by_*()
 *
 * @cell: Cell to be freed
 */
static inline void nvmem_put_cell(struct nvmem_cell *cell)
{
	if (cell->ops->free_cell)
		cell->ops->free_cell(cell);
}

/*
 * nvmem_cell_read() - Allocate and read data from a nvmem cell
 * @cell: Cell to read from nvmem
 * @data: Output allocated buffer where nvmem cell data are stored upon success,
 * shall be released with free().
 * @len: Output byte size of the nvmem cell data read
 */
static inline TEE_Result nvmem_cell_read(struct nvmem_cell *cell,
					 uint8_t **data, size_t *len)
{
	if (!cell->ops->read_cell)
		return TEE_ERROR_NOT_SUPPORTED;

	return cell->ops->read_cell(cell, data, len);
}

#else /* CFG_DRIVERS_NVMEM */
static inline TEE_Result nvmem_register_provider(const void *fdt __unused,
						 int nodeoffset __unused,
						 nvmem_dt_get_func fn __unused,
						 void *data __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result nvmem_get_cell_by_name(const void *fdt __unused,
						int nodeoffset __unused,
						const char *name __unused,
						struct nvmem_cell **c __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result nvmem_get_cell_by_index(const void *fdt,
						 int nodeoffset,
						 unsigned int index,
						 struct nvmem_cell **cell)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result nvmem_cell_parse_dt(const void *fdt __unused,
					     int nodeoffset __unused,
					     struct nvmem_cell *cell __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void nvmem_put_cell(struct nvmem_cell *cell __unused)
{
}
#endif /* CFG_DRIVERS_NVMEM */
#endif /* __DRIVERS_NVMEM_H */
