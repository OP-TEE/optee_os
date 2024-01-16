// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2023, ARM Limited. All rights reserved.
 */

#include <compiler.h>
#include <kernel/dt.h>
#include <kernel/tpm.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <string.h>

static void *tpm_log_addr;
static size_t tpm_log_size;

/*
 * Check whether the node at @offs contains TPM Event Log information or not.
 *
 * @offs is the offset of the node that describes the device in @fdt.
 * @buf will contain the phy address of the TPM Event log.
 * @size will contain the size of the mapped area.
 *
 * Returns the size of the mapped area or < 0 on failure.
 */
#ifdef CFG_DT
static int read_dt_tpm_log_info(void *fdt, int node, paddr_t *buf,
				size_t *size)
{
	const uint32_t *property = NULL;
	const uint64_t zero_addr = 0;
	int len_prop = 0;
	paddr_t log_addr = 0;
	int err = 0;
#ifdef CFG_MAP_EXT_DT_SECURE
	const char *dt_tpm_event_log_addr = "tpm_event_log_addr";
#else
	const char *dt_tpm_event_log_addr = "tpm_event_log_sm_addr";
#endif

	/*
	 * Get the TPM Log address.
	 */
	property = fdt_getprop(fdt, node, dt_tpm_event_log_addr, &len_prop);

	if (!property  || len_prop != sizeof(uint32_t) * 2)
		return -1;

	log_addr = fdt32_to_cpu(property[1]);

	if (!IS_ENABLED(CFG_CORE_SEL1_SPMC)) {
		err = fdt_setprop(fdt, node, dt_tpm_event_log_addr, &zero_addr,
				  sizeof(uint32_t) * 2);
		if (err < 0) {
			EMSG("Error setting property DTB to zero");
			return err;
		}
	}

	/*
	 * Get the TPM Log size.
	 */
	property = fdt_getprop(fdt, node, "tpm_event_log_size", &len_prop);

	if (!property || len_prop != sizeof(uint32_t))
		return -1;

	*size = fdt32_to_cpu(property[0]);
	*buf = log_addr;

	return *size;
}
#endif

static void get_tpm_phys_params(void *fdt __maybe_unused,
				paddr_t *addr, size_t *size)
{
#ifdef CFG_DT
	int node = 0;
	const char *dt_tpm_match_table = {
		"arm,tpm_event_log",
	};

	if (!fdt) {
		EMSG("TPM: No DTB found");
		return;
	}

	node = fdt_node_offset_by_compatible(fdt, -1, dt_tpm_match_table);

	if (node < 0) {
		EMSG("TPM: Fail to find TPM node %i", node);
		return;
	}

	if (read_dt_tpm_log_info((void *)fdt, node, addr, size) < 0) {
		EMSG("TPM: Fail to retrieve DTB properties from node %i",
		     node);
		return;
	}
#else
	*size = CFG_TPM_MAX_LOG_SIZE;
	*addr = CFG_TPM_LOG_BASE_ADDR;
#endif /* CFG_DT */
}

TEE_Result tpm_get_event_log(void *buf, size_t *size)
{
	const size_t buf_size = *size;

	*size = tpm_log_size;
	if (!buf) {
		EMSG("TPM: Invalid buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (buf_size < tpm_log_size) {
		EMSG("TPM: Not enough space for the log: %zu, %zu",
		     buf_size, tpm_log_size);
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(buf, tpm_log_addr, tpm_log_size);

	return TEE_SUCCESS;
}

TEE_Result tpm_get_event_log_size(size_t *size)
{
	*size = tpm_log_size;

	return TEE_SUCCESS;
}

void tpm_map_log_area(void *fdt)
{
	paddr_t log_addr = 0;
	unsigned int rounded_size = 0;

	get_tpm_phys_params(fdt, &log_addr, &tpm_log_size);

	DMSG("TPM Event log PA: %#" PRIxPA, log_addr);
	DMSG("TPM Event log size: %zu Bytes", tpm_log_size);

	rounded_size = ROUNDUP(tpm_log_size, SMALL_PAGE_SIZE);

	tpm_log_addr = core_mmu_add_mapping(MEM_AREA_RAM_SEC, log_addr,
					    rounded_size);
	if (!tpm_log_addr) {
		EMSG("TPM: Failed to map TPM log memory");
		return;
	}
}
