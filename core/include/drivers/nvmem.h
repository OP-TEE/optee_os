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
 * struct nvmem_ops - NVMEM device driver operations
 * @read_cell: Allocate @data in the heap and load @len bytes to from an
 * NVMEM cell
 * @put_cell: Release resources allocated from nvmem_dt_get_func callback
 * function
 */
struct nvmem_ops {
	/*
	 * Read data from an NVMEM cell.
	 * @cell: Cell to read data from
	 * @data: Output buffer of size greater or equal to @cell->size
	 */
	TEE_Result (*read_cell)(struct nvmem_cell *cell, uint8_t *data);
	void (*put_cell)(struct nvmem_cell *cell);
};

/*
 * struct nvmem_cell - Description of an NVMEM cell
 * @offset: Cell byte offset in the NVMEM device
 * @len: Cell byte size
 * @ops: NVMEM device driver operation handlers
 * @drv_data: NVMEM device driver private data
 */
struct nvmem_cell {
	paddr_t offset;
	size_t len;
	const struct nvmem_ops *ops;
	void *drv_data;
};

/*
 * nvmem_dt_get_func - Typedef of handlers to get an NVMEM cell from a npode
 * @args: Reference to phandle arguments
 * @data: Pointer to data given at nvmem_dt_get_func() call
 * @cell: Output reference to cell instance upon success
 *
 * Return TEE_SUCCESS in case of success.
 * Return TEE_ERROR_DEFER_DRIVER_INIT if NVMEM driver is not initialized
 * Return another TEE_Result compliant code otherwise.
 */
typedef TEE_Result (*nvmem_dt_get_func)(struct dt_pargs *args,
					void *data, struct nvmem_cell **cell);

#ifdef CFG_DRIVERS_NVMEM
/**
 * nvmem_register_provider() - Register a NVMEM controller
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of NVMEM cell consumer
 * @get_dt_nvmem: Callback to match the devicetree NVMEM reference with
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
 * nvmem_get_cell_by_name() - Obtain a NVMEM cell from its name in the DT node
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of NVMEM cell consumer
 * @name: name of the NVMEM cell defined by property nvmem-cell-names to obtain
 * from the device tree
 * @cell: Pointer filled with the retrieved cell, must be freed after use
   using nvmem_put_cell()
 * Return a TEE_Result compliant value
 */
TEE_Result nvmem_get_cell_by_name(const void *fdt, int nodeoffset,
				  const char *name, struct nvmem_cell **cell);

/**
 * nvmem_get_cell_by_index() - Obtain a NVMEM cell from property nvmem-cells
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of NVMEM cell consumer
 * @index: Index of the NVMEM cell to obtain from device-tree
 * @out_cell: Pointer filled with the retrieved cell, must be freed after use
 * using nvmem_put_cell()
 * Return a TEE_Result compliant value
 */
TEE_Result nvmem_get_cell_by_index(const void *fdt,
				   int nodeoffset,
				   unsigned int index,
				   struct nvmem_cell **out_cell);

/**
 * nvmem_cell_parse_dt() - Parse device-tree information to fill a NVMEM cell
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the NVMEM cell controller
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
	if (cell->ops->put_cell)
		cell->ops->put_cell(cell);
}

/*
 * nvmem_cell_read() - Read data from a NVMEM cell
 * @cell: Cell to read from NVMEM
 * @data: Output data read from the cell upon success, byte size >= @cell->size
 */
static inline TEE_Result nvmem_cell_read(struct nvmem_cell *cell,
					 uint8_t *data)
{
	if (!cell->ops->read_cell)
		return TEE_ERROR_NOT_SUPPORTED;

	return cell->ops->read_cell(cell, data);
}

/*
 * nvmem_cell_malloc_and_read() - Allocate and read data from a NVMEM cell
 * @cell: Cell to read from NVMEM
 * @data: Output allocated buffer where NVMEM cell data are stored upon success
 *
 * Upon success, the output buffer is allocated with malloc(). Caller is
 * responsible for freeing the buffer with free() if needed.
 */
TEE_Result nvmem_cell_malloc_and_read(struct nvmem_cell *cell,
				      uint8_t **out_data);

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

static inline
TEE_Result nvmem_get_cell_by_index(const void *fdt __unused,
				   int nodeoffset __unused,
				   unsigned int index __unused,
				   struct nvmem_cell **cell __unused)
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
