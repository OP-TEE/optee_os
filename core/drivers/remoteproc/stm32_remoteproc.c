// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32_remoteproc.h>
#include <kernel/cache_helpers.h>
#include <kernel/dt_driver.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>

#define TIMEOUT_US_1MS	U(1000)

/**
 * struct stm32_rproc_mem - Memory regions used by the remote processor
 *
 * @addr:	physical base address from the CPU space perspective
 * @da:		device address corresponding to the physical base address
 *		from remote processor space perspective
 * @size:	size of the region
 */
struct stm32_rproc_mem {
	paddr_t addr;
	paddr_t da;
	size_t size;
};

/**
 * struct stm32_rproc_instance - rproc instance context
 *
 * @cdata:	pointer to the device compatible data
 * @link:	the node in the rproc_list
 * @n_regions:	number of memory regions
 * @regions:	memory regions used
 * @mcu_rst:	remote processor reset control
 * @hold_boot:	remote processor hold boot control
 */
struct stm32_rproc_instance {
	const struct stm32_rproc_compat_data *cdata;
	SLIST_ENTRY(stm32_rproc_instance) link;
	size_t n_regions;
	struct stm32_rproc_mem *regions;
	struct rstctrl *mcu_rst;
	struct rstctrl *hold_boot;
};

/**
 * struct stm32_rproc_compat_data - rproc associated data for compatible list
 *
 * @rproc_id:	identifies the remote processor
 */
struct stm32_rproc_compat_data {
	uint32_t rproc_id;
};

static SLIST_HEAD(, stm32_rproc_instance) rproc_list =
		SLIST_HEAD_INITIALIZER(rproc_list);

void *stm32_rproc_get(uint32_t rproc_id)
{
	struct stm32_rproc_instance *rproc = NULL;

	SLIST_FOREACH(rproc, &rproc_list, link)
		if (rproc->cdata->rproc_id == rproc_id)
			break;

	return rproc;
}

TEE_Result stm32_rproc_start(uint32_t rproc_id)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(rproc_id);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rproc || !rproc->hold_boot)
		return TEE_ERROR_GENERIC;

	/*
	 * The firmware is started by de-asserting the hold boot and
	 * asserting it back to avoid auto restart on a crash.
	 * No need to release the MCU reset as it is automatically released by
	 * the hardware.
	 */
	res = rstctrl_deassert_to(rproc->hold_boot, TIMEOUT_US_1MS);
	if (!res)
		res = rstctrl_assert_to(rproc->hold_boot, TIMEOUT_US_1MS);

	return res;
}

static TEE_Result rproc_stop(struct stm32_rproc_instance *rproc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rproc->hold_boot || !rproc->mcu_rst)
		return TEE_ERROR_GENERIC;

	res = rstctrl_assert_to(rproc->hold_boot, TIMEOUT_US_1MS);
	if (!res)
		res = rstctrl_assert_to(rproc->mcu_rst, TIMEOUT_US_1MS);

	return res;
}

TEE_Result stm32_rproc_stop(uint32_t rproc_id)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(rproc_id);

	if (!rproc)
		return TEE_ERROR_BAD_PARAMETERS;

	return rproc_stop(rproc);
}

TEE_Result stm32_rproc_da_to_pa(uint32_t rproc_id, paddr_t da, size_t size,
				paddr_t *pa)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(rproc_id);
	struct stm32_rproc_mem *mems = NULL;
	unsigned int i = 0;

	if (!rproc)
		return TEE_ERROR_BAD_PARAMETERS;

	mems = rproc->regions;

	for (i = 0; i < rproc->n_regions; i++) {
		if (core_is_buffer_inside(da, size, mems[i].da, mems[i].size)) {
			/*
			 * A match between the requested DA memory area and the
			 * registered regions has been found.
			 * The PA is the reserved-memory PA address plus the
			 * delta between the requested DA and the
			 * reserved-memory DA address.
			 */
			*pa = mems[i].addr + da - mems[i].da;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result stm32_rproc_map(uint32_t rproc_id, paddr_t pa, size_t size,
			   void **va)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(rproc_id);
	struct stm32_rproc_mem *mems = NULL;
	unsigned int i = 0;

	if (!rproc)
		return TEE_ERROR_BAD_PARAMETERS;

	mems = rproc->regions;

	for (i = 0; i < rproc->n_regions; i++) {
		if (!core_is_buffer_inside(pa, size, mems[i].addr,
					   mems[i].size))
			continue;
		*va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, size);
		if (!*va) {
			EMSG("Can't map region %#"PRIxPA" size %zu", pa, size);
			return TEE_ERROR_GENERIC;
		}

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result stm32_rproc_unmap(uint32_t rproc_id, void *va, size_t size)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(rproc_id);
	struct stm32_rproc_mem *mems = NULL;
	paddr_t pa = virt_to_phys(va);
	unsigned int i = 0;

	if (!rproc || !pa)
		return TEE_ERROR_BAD_PARAMETERS;

	mems = rproc->regions;

	for (i = 0; i < rproc->n_regions; i++) {
		if (!core_is_buffer_inside(pa, size, mems[i].addr,
					   mems[i].size))
			continue;

		/* Flush the cache before unmapping the memory */
		dcache_clean_range(va, size);

		if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, va, size)) {
			EMSG("Can't unmap region %#"PRIxPA" size %zu",
			     pa, size);
			return TEE_ERROR_GENERIC;
		}

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result stm32_rproc_get_dma_range(struct stm32_rproc_mem *region,
					    const void *fdt, int node)
{
	const fdt32_t *list = NULL;
	int ahb_node = 0;
	int len = 0;
	int nranges = 0;
	int i = 0;

	/*
	 * The match between local and remote processor memory mapping is
	 * described in the dma-ranges defined by the bus parent node.
	 */
	ahb_node = fdt_parent_offset(fdt, node);

	list = fdt_getprop(fdt, ahb_node, "dma-ranges", &len);
	if (!list) {
		if (len != -FDT_ERR_NOTFOUND)
			return TEE_ERROR_GENERIC;
		/* Same memory mapping */
		DMSG("No dma-ranges found in DT");
		region->da = region->addr;
		return TEE_SUCCESS;
	}

	if ((len % (sizeof(uint32_t) * 3)))
		return TEE_ERROR_GENERIC;

	nranges = len / sizeof(uint32_t);

	for (i = 0; i < nranges; i += 3) {
		uint32_t da = fdt32_to_cpu(list[i]);
		uint32_t pa = fdt32_to_cpu(list[i + 1]);
		uint32_t size = fdt32_to_cpu(list[i + 2]);

		if (core_is_buffer_inside(region->addr, region->size,
					  pa, size)) {
			region->da = da + (region->addr - pa);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/* Get device tree memory regions reserved for the Cortex-M and the IPC */
static TEE_Result stm32_rproc_parse_mems(struct stm32_rproc_instance *rproc,
					 const void *fdt, int node)
{
	const fdt32_t *list = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_rproc_mem *regions = NULL;
	int len = 0;
	int n_regions = 0;
	int i = 0;

	list = fdt_getprop(fdt, node, "memory-region", &len);
	if (!list) {
		EMSG("No memory regions found in DT");
		return TEE_ERROR_GENERIC;
	}

	n_regions = len / sizeof(uint32_t);

	regions = calloc(n_regions, sizeof(*regions));
	if (!regions)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < n_regions; i++) {
		int pnode = 0;

		pnode = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(list[i]));
		if (pnode < 0) {
			res = TEE_ERROR_GENERIC;
			goto err;
		}

		regions[i].addr = fdt_reg_base_address(fdt, pnode);
		regions[i].size = fdt_reg_size(fdt, pnode);

		if (regions[i].addr <= 0 || regions[i].size <= 0) {
			res = TEE_ERROR_GENERIC;
			goto err;
		}

		res = stm32_rproc_get_dma_range(&regions[i], fdt, node);
		if (res)
			goto err;

		if (!regions[i].addr || !regions[i].size) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		DMSG("register region %#"PRIxPA" size %#zx",
		     regions[i].addr, regions[i].size);
	}

	rproc->n_regions = n_regions;
	rproc->regions = regions;

	return TEE_SUCCESS;

err:
	free(regions);

	return res;
}

static void stm32_rproc_cleanup(struct stm32_rproc_instance *rproc)
{
	free(rproc->regions);
	free(rproc);
}

static TEE_Result stm32_rproc_probe(const void *fdt, int node,
				    const void *comp_data)
{
	struct stm32_rproc_instance *rproc = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	rproc = calloc(1, sizeof(*rproc));
	if (!rproc)
		return TEE_ERROR_OUT_OF_MEMORY;

	rproc->cdata = comp_data;

	res = stm32_rproc_parse_mems(rproc, fdt, node);
	if (res)
		goto err;

	res = rstctrl_dt_get_by_name(fdt, node, "mcu_rst", &rproc->mcu_rst);
	if (res)
		goto err;

	res = rstctrl_dt_get_by_name(fdt, node, "hold_boot", &rproc->hold_boot);
	if (res)
		goto err;

	/* Ensure that the MCU is HOLD */
	if (rproc->mcu_rst) {
		res = rproc_stop(rproc);
		if (res)
			goto err;
	}

	/*
	 * The memory management should be enhance with firewall
	 * mechanism to map the memory in secure area for the firmware
	 * loading and then to give exclusive access right to the
	 * coprocessor (except for the shared memory).
	 */
	IMSG("Warning: the remoteproc memories are not protected by firewall");

	SLIST_INSERT_HEAD(&rproc_list, rproc, link);

	return TEE_SUCCESS;

err:
	stm32_rproc_cleanup(rproc);
	return res;
}

static const struct stm32_rproc_compat_data stm32_rproc_m4_compat = {
	.rproc_id = STM32_M4_RPROC_ID,
};

static const struct dt_device_match stm32_rproc_match_table[] = {
	{
		.compatible = "st,stm32mp1-m4-tee",
		.compat_data = &stm32_rproc_m4_compat,
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_rproc_dt_driver) = {
	.name = "stm32-rproc",
	.match_table = stm32_rproc_match_table,
	.probe = &stm32_rproc_probe,
};
