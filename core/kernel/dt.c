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

#include <console.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <trace.h>
#include <utee_defines.h>

/*
 * DT manipulation helpers
 */

static const void *__fdt;

const void *dt_fdt(void)
{
	return __fdt;
}

int dt_validate(const void *fdt)
{
	if (!fdt || fdt_check_header(fdt) < 0) {
		EMSG("Invalid or missing Device Tree");
		return -1;
	}
	__fdt = fdt;
	DMSG("Using Device Tree at %p", __fdt);

	return 0;
}

static int read_be32(const char *v)
{
	return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
}

int dt_n_addr_cells(int nodeoffset)
{
	const struct fdt_property *prop;
	int len;

	do {
		prop = fdt_get_property(__fdt, nodeoffset, "#address-cells",
					&len);
		if (prop) {
			if (len != 4)
				goto bad;
			return read_be32(prop->data);
		}
		nodeoffset = fdt_parent_offset(__fdt, nodeoffset);
	} while (nodeoffset >= 0);

bad:
	return 0;
}

paddr_t dt_read_paddr(const uint32_t *cell, int n)
{
	paddr_t addr;

	if (n < 0 || n > 2)
		goto bad;

	if (sizeof(paddr_t) == 2 && n == 2 && *cell)
		goto bad;

	addr = TEE_U32_FROM_BIG_ENDIAN(*cell);
	cell++;
	if (n == 2) {
#ifdef ARM32
		if (*cell)
			goto bad;
#else
		addr = (addr << 32) | TEE_U32_FROM_BIG_ENDIAN(*cell);
#endif
	}

	return addr;
bad:
	return (paddr_t)-1;
}

paddr_t dt_reg_base_address(int node_offset)
{
	const void *reg;
	int len;
	int ncells;

	reg = fdt_getprop(__fdt, node_offset, "reg", &len);
	if (!reg)
		return (paddr_t)-1;
	ncells = dt_n_addr_cells(node_offset);
	if (!ncells)
		return (paddr_t)-1;
	return dt_read_paddr(reg, ncells);
}

/*
 * DT-aware drivers
 */

extern struct dt_driver __rodata_dtdrv_start, __rodata_dtdrv_end;

const struct dt_driver *dt_find_driver(const char *compatible __unused)
{
	const struct dt_driver *drv = NULL;

	for_each_dt_driver(drv)
		DMSG("Checking DT driver: %s (compatible: %s)", drv->name,
		     drv->compatible);

	return drv;
}

const struct dt_driver *__dt_driver_start(void)
{
	return &__rodata_dtdrv_start;
}

const struct dt_driver *__dt_driver_end(void)
{
	return &__rodata_dtdrv_end;
}

