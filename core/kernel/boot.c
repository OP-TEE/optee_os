// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2023, Linaro Limited
 * Copyright (c) 2023, Arm Limited
 */

#include <crypto/crypto.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>

#ifdef CFG_CORE_DYN_SHM
static uint64_t get_dt_val_and_advance(const void *data, size_t *offs,
				       uint32_t cell_size)
{
	uint64_t rv = 0;

	if (cell_size == 1) {
		uint32_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt32_to_cpu(v);
	} else {
		uint64_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt64_to_cpu(v);
	}

	return rv;
}

/*
 * Find all non-secure memory from DT. Memory marked inaccessible by Secure
 * World is ignored since it could not be mapped to be used as dynamic shared
 * memory.
 */
static int __maybe_unused get_nsec_memory_helper(void *fdt,
						 struct core_mmu_phys_mem *mem,
						 const char *dev_type)
{
	size_t dev_type_size = strlen(dev_type) + 1;
	const uint8_t *prop = NULL;
	uint64_t a = 0;
	uint64_t l = 0;
	size_t prop_offs = 0;
	size_t prop_len = 0;
	int elems_total = 0;
	int addr_size = 0;
	int len_size = 0;
	int offs = 0;
	size_t n = 0;
	int len = 0;

	addr_size = fdt_address_cells(fdt, 0);
	if (addr_size < 0)
		return 0;

	len_size = fdt_size_cells(fdt, 0);
	if (len_size < 0)
		return 0;

	while (true) {
		offs = fdt_node_offset_by_prop_value(fdt, offs, "device_type",
						     dev_type, dev_type_size);
		if (offs < 0)
			break;

		if (fdt_get_status(fdt, offs) != (DT_STATUS_OK_NSEC |
						   DT_STATUS_OK_SEC))
			continue;

		prop = fdt_getprop(fdt, offs, "reg", &len);
		if (!prop)
			continue;

		prop_len = len;
		for (n = 0, prop_offs = 0; prop_offs < prop_len; n++) {
			a = get_dt_val_and_advance(prop, &prop_offs, addr_size);
			if (prop_offs >= prop_len) {
				n--;
				break;
			}

			l = get_dt_val_and_advance(prop, &prop_offs, len_size);
			if (mem) {
				mem->type = MEM_AREA_DDR_OVERALL;
				mem->addr = a;
				mem->size = l;
				mem++;
			}
		}

		elems_total += n;
	}

	return elems_total;
}

#ifdef CFG_DT
static struct core_mmu_phys_mem *get_nsec_memory(void *fdt, size_t *nelems,
						 const char *dev_type)
{
	struct core_mmu_phys_mem *mem = NULL;
	int elems_total = 0;

	elems_total = get_nsec_memory_helper(fdt, NULL, dev_type);
	if (elems_total <= 0)
		return NULL;

	mem = nex_calloc(elems_total, sizeof(*mem));
	if (!mem)
		panic();

	elems_total = get_nsec_memory_helper(fdt, mem, dev_type);
	assert(elems_total > 0);

	*nelems = elems_total;

	return mem;
}
#else /*CFG_DT*/
static struct core_mmu_phys_mem *get_nsec_memory(void *fdt __unused,
						 size_t *nelems __unused,
						 const char *dev_type __unused)
{
	return NULL;
}
#endif /*!CFG_DT*/

void discover_nsec_memory(void)
{
	struct core_mmu_phys_mem *mem = NULL;
	const struct core_mmu_phys_mem *mem_begin = NULL;
	const struct core_mmu_phys_mem *mem_end = NULL;
	size_t nelems = 0;
	void *fdt = NULL;

	fdt = get_manifest_dt();
	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems, "ns-memory");
		if (mem) {
			DMSG("Non-secure memory found in manifest DT");
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in manifest DT");
	}

	fdt = get_external_dt();
	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems, "memory");
		if (mem) {
			DMSG("Non-secure memory found in extern DT");
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in external DT");
	}

	fdt = get_embedded_dt();
	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems, "memory");
		if (mem) {
			DMSG("Non-secure memory found in embedded DT");
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in embedded DT");
	}

	mem_begin = phys_ddr_overall_begin;
	mem_end = phys_ddr_overall_end;
	nelems = mem_end - mem_begin;
	if (nelems) {
		/*
		 * Platform cannot use both register_ddr() and the now
		 * deprecated register_dynamic_shm().
		 */
		assert(phys_ddr_overall_compat_begin ==
		       phys_ddr_overall_compat_end);
	} else {
		mem_begin = phys_ddr_overall_compat_begin;
		mem_end = phys_ddr_overall_compat_end;
		nelems = mem_end - mem_begin;
		if (!nelems)
			return;
		DMSG("Warning register_dynamic_shm() is deprecated, "
		     "please use register_ddr() instead");
	}

	mem = nex_calloc(nelems, sizeof(*mem));
	if (!mem)
		panic();

	memcpy(mem, phys_ddr_overall_begin, sizeof(*mem) * nelems);
	core_mmu_set_discovered_nsec_ddr(mem, nelems);
}
#else /*CFG_CORE_DYN_SHM*/
void discover_nsec_memory(void)
{
}
#endif /*!CFG_CORE_DYN_SHM*/

#ifdef CFG_CORE_RESERVED_SHM
int mark_static_shm_as_reserved(struct dt_descriptor *dt)
{
	vaddr_t shm_start;
	vaddr_t shm_end;

	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &shm_start, &shm_end);
	if (shm_start != shm_end)
		return add_res_mem_dt_node(dt, "optee_shm",
					   virt_to_phys((void *)shm_start),
					   shm_end - shm_start);

	DMSG("No SHM configured");
	return -1;
}
#endif /*CFG_CORE_RESERVED_SHM*/

#if defined(_CFG_CORE_STACK_PROTECTOR) || defined(CFG_WITH_STACK_CANARIES)
/* Generate random stack canary value on boot up */
__weak void plat_get_random_stack_canaries(void *buf, size_t ncan, size_t size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t i = 0;

	assert(buf && ncan && size);

	/*
	 * With virtualization the RNG is not initialized in Nexus core.
	 * Need to override with platform specific implementation.
	 */
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		IMSG("WARNING: Using fixed value for stack canary");
		memset(buf, 0xab, ncan * size);
		goto out;
	}

	ret = crypto_rng_read(buf, ncan * size);
	if (ret != TEE_SUCCESS)
		panic("Failed to generate random stack canary");

out:
	/* Leave null byte in canary to prevent string base exploit */
	for (i = 0; i < ncan; i++)
		*((uint8_t *)buf + size * i) = 0;
}
#endif /* _CFG_CORE_STACK_PROTECTOR || CFG_WITH_STACK_CANARIES */
