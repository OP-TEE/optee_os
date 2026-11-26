// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 HiSilicon Limited. */

#include <drivers/device_dt.h>

static void *get_fdt(void)
{
	void *fdt = NULL;

#if defined(CFG_BIOS_DTB)
	enum teecore_memtypes mtype;
	mtype = core_mmu_get_type_by_pa((paddr_t)bios_dtb);
	fdt = phys_to_virt((paddr_t)bios_dtb, mtype,
			   sizeof(BIOS_DTB_SIZE));
#else
	fdt = get_dt();
#endif

	return fdt;
}

TEE_Result set_device_info_by_node(uintptr_t *io_base, uint32_t *io_size,
				   void *fdt, int node)
{
	const fdt64_t *p64 = NULL;
	const fdt32_t *p32 = NULL;
	uint32_t pages_cnt = 0;
	uintptr_t base = 0;
	int len = 0;

	/* base-address: 64-bit property, big-endian in the blob */
	p64 = fdt_getprop(fdt, node, "base-address", &len);
	if (!p64 || len != sizeof(*p64)) {
		EMSG("Fail to get field base-address\n");
		return TEE_ERROR_BAD_FORMAT;
	}
	base = fdt64_ld(p64);

	/* pages-count: 32-bit property, big-endian in the blob */
	p32 = fdt_getprop(fdt, node, "pages-count", &len);
	if (!p32 || len != sizeof(*p32)) {
		EMSG("Fail to get field pages-count\n");
		return TEE_ERROR_BAD_FORMAT;
	}
	pages_cnt = fdt32_ld(p32);

	*io_base = base;
	*io_size = pages_cnt * SMALL_PAGE_SIZE;

	return TEE_SUCCESS;
}

TEE_Result set_device_info_by_dt(uintptr_t *io_base, uint32_t *io_size,
				 const char *dt_dev_match)
{
	void *fdt = NULL;
	int node = 0;

	fdt = get_fdt();
	if (!fdt) {
		EMSG("Fail to get valid dtb");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	node = fdt_node_offset_by_compatible(fdt, -1, dt_dev_match);
	if (node < 0) {
		EMSG("Fail to find  %s compatible node", dt_dev_match);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return set_device_info_by_node(io_base, io_size, fdt, node);
}

TEE_Result device_init_by_dt(TEE_Result (*device_probe)(void *fdt, int node),
			     const char *dt_dev_match)
{
	void *fdt = NULL;
	int parent = 0;
	int node = 0;
	int cnt = 0;

	fdt = get_fdt();
	if (!fdt) {
		EMSG("Fail to get valid dtb");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	parent = fdt_node_offset_by_compatible(fdt, -1,
					       "arm,ffa-manifest-device-regions");
	if (parent < 0) {
		EMSG("Fail to find device-regions compatible node");
		return TEE_ERROR_BAD_FORMAT;
	}

	fdt_for_each_subnode(node, fdt, parent) {
		if (fdt_node_check_compatible(fdt, node, dt_dev_match))
			continue;

		if (device_probe(fdt, node) != TEE_SUCCESS) {
			EMSG("Fail to init device %s",
			     fdt_get_name(fdt, node, NULL));
			continue;
		}

		cnt++;
	}

	return (cnt ? TEE_SUCCESS : TEE_ERROR_NOT_IMPLEMENTED);
}
