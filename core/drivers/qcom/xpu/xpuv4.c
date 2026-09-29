// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/xpuv4.h>
#include <io.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/*
 * XPU4 register offsets.
 * IDR0 reports the highest resource group (RG) index in NRG. Each RG
 * occupies 0x40 bytes starting at base + 0x1000.
 *   IDR0     +0x0000  NRG = bits 25:16
 *   RGCR1n   +0x1004  bit 0 = RGE (enable)
 *   RGCSAR1n +0x1008  start address [63:32]
 *   RGCSAR0n +0x100C  start address [31:0]
 *   RGCEAR1n +0x1010  end   address [63:32]
 *   RGCEAR0n +0x1014  end   address [31:0]
 *   RGRDRn   +0x1018  read  QAD vector
 *   RGWRRn   +0x101C  write QAD vector
 *   QADRGLn  +0x1030  QAD lock vector (bit 31 = secure lock RGL_S)
 */
#define XPU4_IDR0(b)        ((b) + 0x0u)
#define XPU4_RGCR1n(b, n)   ((b) + 0x1004u + 0x40u * (n))
#define XPU4_RGCSAR1n(b, n) ((b) + 0x1008u + 0x40u * (n))
#define XPU4_RGCSAR0n(b, n) ((b) + 0x100Cu + 0x40u * (n))
#define XPU4_RGCEAR1n(b, n) ((b) + 0x1010u + 0x40u * (n))
#define XPU4_RGCEAR0n(b, n) ((b) + 0x1014u + 0x40u * (n))
#define XPU4_RGRDRn(b, n)   ((b) + 0x1018u + 0x40u * (n))
#define XPU4_RGWRRn(b, n)   ((b) + 0x101Cu + 0x40u * (n))
#define XPU4_QADRGLn(b, n)  ((b) + 0x1030u + 0x40u * (n))

#define XPU4_IDR0_NRG_MASK	SHIFT_U32(0x3FF, 16)
#define XPU4_IDR0_NRG_SHIFT	16

#define XPU4_RGCR1n_RGE		BIT32(0)

/* Instances the platform registered, describing this SoC's XPU layout */
static const struct xpu4_instance *xpu4_instances;
static size_t xpu4_instance_count;

void xpu4_register_instances(const struct xpu4_instance *instances,
			     size_t count)
{
	xpu4_instances = instances;
	xpu4_instance_count = count;
}

static const struct xpu4_instance *xpu4_find_instance(paddr_t start,
						      size_t size)
{
	const struct xpu4_instance *inst = NULL;
	size_t i = 0;

	for (i = 0; i < xpu4_instance_count; i++) {
		inst = &xpu4_instances[i];

		if (core_is_buffer_inside(start, size, inst->guard_start,
					  inst->guard_size))
			return inst;
	}

	return NULL;
}

static TEE_Result xpu4_find_free_rg(vaddr_t base,
				    const struct xpu4_instance *inst,
				    unsigned int *rg)
{
	unsigned int rg_end = inst->rg_start + inst->rg_count;
	unsigned int nrg = 0;
	unsigned int i = 0;

	/* IDR0 reports the highest RG index, so the count is one more */
	nrg = ((io_read32(XPU4_IDR0(base)) & XPU4_IDR0_NRG_MASK) >>
	       XPU4_IDR0_NRG_SHIFT) + 1;
	if (rg_end > nrg) {
		EMSG("XPU: RG window %u..%u exceeds %u RGs implemented",
		     inst->rg_start, rg_end - 1, nrg);
		return TEE_ERROR_BAD_STATE;
	}

	for (i = inst->rg_start; i < rg_end; i++) {
		if (io_read32(XPU4_RGCR1n(base, i)) & XPU4_RGCR1n_RGE)
			continue;

		*rg = i;
		return TEE_SUCCESS;
	}

	EMSG("XPU: no free RG in window %u..%u", inst->rg_start, rg_end - 1);
	return TEE_ERROR_OUT_OF_MEMORY;
}

static void xpu4_program_rg(vaddr_t base, unsigned int rg, paddr_t start,
			    paddr_t end, uint32_t read_qad, uint32_t write_qad,
			    uint32_t lock_qad)
{
	io_write32(XPU4_RGCSAR1n(base, rg), (uint32_t)(start >> 32));
	io_write32(XPU4_RGCSAR0n(base, rg), (uint32_t)start);
	io_write32(XPU4_RGCEAR1n(base, rg), (uint32_t)(end >> 32));
	io_write32(XPU4_RGCEAR0n(base, rg), (uint32_t)end);
	io_write32(XPU4_RGRDRn(base, rg), read_qad);
	io_write32(XPU4_RGWRRn(base, rg), write_qad);
	io_write32(XPU4_RGCR1n(base, rg), XPU4_RGCR1n_RGE);
	io_write32(XPU4_QADRGLn(base, rg), lock_qad);
}

TEE_Result xpu_protect_region(paddr_t start, size_t size,
			      uint32_t read_perm, uint32_t write_perm)
{
	const struct xpu4_instance *inst = NULL;
	uint32_t lock_perm = 0;
	unsigned int rg = 0;
	paddr_t xpu_start = 0;
	paddr_t xpu_end = 0;
	vaddr_t base = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* XPU4 requires 4KB-aligned, non-zero start and end addresses */
	if (!size || !IS_ALIGNED(start, SIZE_4K) ||
	    !IS_ALIGNED(size, SIZE_4K)) {
		EMSG("XPU: region %#" PRIxPA "+%#zx not 4KB aligned",
		     start, size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	inst = xpu4_find_instance(start, size);
	if (!inst) {
		EMSG("XPU: no instance guards region %#" PRIxPA "+%#zx",
		     start, size);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Addresses are relative to the region base; the end is exclusive */
	if (SUB_OVERFLOW(start, inst->addr_off, &xpu_start) ||
	    ADD_OVERFLOW(xpu_start, size, &xpu_end)) {
		EMSG("XPU: region %#" PRIxPA "+%#zx invalid for offset %#"
		     PRIxPA, start, size, inst->addr_off);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	lock_perm = (read_perm | write_perm) & QAD_ENV_APPS;
	if (!lock_perm) {
		EMSG("XPU: no AP domain in region perms, refusing to program");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	base = io_pa_or_va_secure(&(struct io_pa_va){ .pa = inst->base },
				  inst->map_size);

	res = xpu4_find_free_rg(base, inst, &rg);
	if (res)
		return res;

	xpu4_program_rg(base, rg, xpu_start, xpu_end,
			read_perm, write_perm, lock_perm);

	return TEE_SUCCESS;
}
