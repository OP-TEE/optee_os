/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KERNEL_DT_H
#define KERNEL_DT_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <util.h>

/*
 * Bitfield to reflect status and secure-status values ("ok", "disabled" or not
 * present)
 */
#define DT_STATUS_DISABLED 0
#define DT_STATUS_OK_NSEC  BIT(0)
#define DT_STATUS_OK_SEC   BIT(1)

#if defined(CFG_DT)

/*
 * DT-aware drivers
 */

struct dt_device_match {
	const char *compatible;
};

struct dt_driver {
	const char *name;
	const struct dt_device_match *match_table; /* null-terminated */
	const void *driver;
};

#define __dt_driver __section(".rodata.dtdrv")

/*
 * Find a driver that is suitable for the given DT node, that is, with
 * a matching "compatible" property.
 *
 * @fdt: pointer to the device tree
 * @offs: node offset
 */
const struct dt_driver *dt_find_compatible_driver(const void *fdt, int offs);

const struct dt_driver *__dt_driver_start(void);

const struct dt_driver *__dt_driver_end(void);

/*
 * Map a device into secure or non-secure memory and return the base VA and
 * the mapping size. The mapping is done with type MEM_AREA_IO_SEC or
 * MEM_AREA_IO_NSEC, depending on the device status.
 * If the mapping already exists, the function simply returns the @vbase and
 * @size information.
 *
 * @offs is the offset of the node that describes the device in @fdt.
 * @base receives the base virtual address corresponding to the base physical
 * address of the "reg" property
 * @size receives the size of the mapping
 *
 * Returns 0 on success or -1 in case of error.
 */
int dt_map_dev(const void *fdt, int offs, vaddr_t *base, size_t *size);

/*
 * FDT manipulation functions, not provided by <libfdt.h>
 */

/*
 * Return the base address for the "reg" property of the specified node or
 * (paddr_t)-1 in case of error
 */
paddr_t _fdt_reg_base_address(const void *fdt, int offs);

/*
 * Return the reg size for the reg property of the specified node or -1 in case
 * of error
 */
ssize_t _fdt_reg_size(const void *fdt, int offs);

/*
 * Read the status and secure-status properties into a bitfield.
 * @status is set to DT_STATUS_DISABLED or a combination of DT_STATUS_OK_NSEC
 * and DT_STATUS_OK_SEC
 * Returns 0 on success or -1 in case of error.
 */
int _fdt_get_status(const void *fdt, int offs);

#else /* !CFG_DT */

static inline const struct dt_driver *__dt_driver_start(void)
{
	return NULL;
}

static inline const struct dt_driver *__dt_driver_end(void)
{
	return NULL;
}

static inline const struct dt_driver *dt_find_compatible_driver(
					const void *fdt __unused,
					int offs __unused)
{
	return NULL;
}

static inline int dt_map_dev(const void *fdt __unused, int offs __unused,
			     vaddr_t *vbase __unused, size_t *size __unused)
{
	return -1;
}

static inline paddr_t _fdt_reg_base_address(const void *fdt __unused,
					    int offs __unused)
{
	return (paddr_t)-1;
}

static inline ssize_t _fdt_reg_size(const void *fdt __unused,
				    int offs __unused)
{
	return -1;
}

static inline int _fdt_get_status(const void *fdt __unused, int offs __unused)
{
	return -1;
}

#endif /* !CFG_DT */

#define for_each_dt_driver(drv) \
	for (drv = __dt_driver_start(); drv < __dt_driver_end(); drv++)

#endif /* KERNEL_DT_H */
