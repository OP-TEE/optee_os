/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Firmware resource table helpers for Qualcomm remoteproc subsystems.
 *
 * A resource table is a data structure embedded in (or alongside) a processor
 * firmware image.  It advertises to the host the set of memory regions the
 * processor needs mapped into its IOMMU before it can boot.  The layout
 * expected by the remoteproc / PAS loader is:
 *
 *   [ struct resource_table header + offset[] array ]
 *   [ struct fw_rsc_hdr + struct fw_rsc_devmem ] * N   <- one per region
 *
 * Each element in offset[] holds the byte offset from the start of the table
 * to the corresponding fw_rsc_hdr/fw_rsc_devmem pair.
 *
 * Callers define a table with DEFINE_RESOURCE_TABLE(), declare a static
 * struct resource_table and a static array of struct fw_rsc_devmem, then
 * call get_mem_rsc() to serialise everything into a caller-supplied buffer.
 */

#ifndef RESOURCE_TABLE_H
#define RESOURCE_TABLE_H

#include <compiler.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <util.h>

/*
 * DEFINE_RESOURCE_TABLE(prefix, num_res) : emit compile-time size constants
 * for a resource table that holds @num_res device-memory entries.
 *
 * Generates an anonymous enum with four members, all prefixed by @prefix:
 *
 *   PREFIX_NUM_MEM_RESOURCES        : number of fw_rsc_devmem entries
 *   PREFIX_SIZE_MEM_RES             : byte size of one (hdr + devmem) entry
 *   PREFIX_RESOURCE_TABLE_HEADER_SIZE : byte size of the table header plus
 *                                       the offset[] array
 *   PREFIX_RESOURCE_TABLE_SIZE      : total byte size of the serialised table
 *
 * Use these constants to size the struct resource_table initialiser and to
 * pass table_header_size / table_size to get_mem_rsc().
 */
#define DEFINE_RESOURCE_TABLE(prefix, num_res)			\
	enum prefix##_rt_sizes {				\
		prefix##_NUM_MEM_RESOURCES = (num_res),		\
		prefix##_SIZE_MEM_RES =				\
			(sizeof(struct fw_rsc_hdr) +		\
			 sizeof(struct fw_rsc_devmem)),		\
		prefix##_RESOURCE_TABLE_HEADER_SIZE =		\
			(sizeof(struct resource_table) +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  sizeof(uint32_t))),			\
		prefix##_RESOURCE_TABLE_SIZE =			\
			(prefix##_RESOURCE_TABLE_HEADER_SIZE +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  prefix##_SIZE_MEM_RES)),		\
	}

/*
 * resource_table : top-level header of the firmware resource table.
 *
 * @ver:      Table version; must be 1.
 * @num:      Number of resource entries (length of the offset[] array).
 * @reserved: Must be zero.
 * @offset:   Array of byte offsets from the start of the table to each
 *            fw_rsc_hdr entry.  Populated by get_mem_rsc().
 */
struct resource_table {
	uint32_t ver;
	uint32_t num;
	uint32_t reserved[2];
	uint32_t offset[];
} __packed;

/*
 * fw_rsc_hdr : per-resource entry header.
 *
 * @type: Resource type (see enum fw_resource_type).
 * @data: Type-specific payload; for RSC_DEVMEM this is struct fw_rsc_devmem.
 */
struct fw_rsc_hdr {
	uint32_t type;
	uint8_t data[];
} __packed;

/* Resource entry types defined by the remoteproc ABI. */
enum fw_resource_type {
	RSC_CARVEOUT		= 0,  /* contiguous memory carve-out */
	RSC_DEVMEM		= 1,  /* device memory IOMMU mapping */
	RSC_TRACE		= 2,  /* trace buffer */
	RSC_VDEV		= 3,  /* virtio device */
	RSC_LAST		= 4,
	RSC_VENDOR_START	= 128,
	RSC_VENDOR_END		= 512,
};

/* IOMMU permission flags for fw_rsc_devmem.flags. */
#define IOMMU_READ	BIT(0)
#define IOMMU_WRITE	BIT(1)

/*
 * fw_rsc_devmem : describes a single IOMMU mapping the processor requires.
 *
 * @da:       Device virtual address of the mapping.
 * @pa:       Physical address; on Kodiak these are identity-mapped (da == pa).
 * @len:      Size of the region in bytes.
 * @flags:    IOMMU permission flags (IOMMU_READ, IOMMU_WRITE).
 * @reserved: Must be zero.
 * @name:     Human-readable label for debugging (NUL-terminated, 32 bytes).
 */
struct fw_rsc_devmem {
	uint32_t da;
	uint32_t pa;
	uint32_t len;
	uint32_t flags;
	uint32_t reserved;
	uint8_t name[32];
} __packed;

/*
 * get_mem_rsc() : serialise a processor resource table into a caller buffer.
 *
 * The function has two modes:
 *
 *   Size query: pass rt == NULL (or *rt_size < table_size).  The required
 *   buffer size is written to *rt_size and TEE_SUCCESS is returned so the
 *   caller can allocate an appropriately-sized buffer.
 *
 *   Serialise: pass a buffer of at least table_size bytes in rt.  The
 *   function fills in table->offset[], copies each (mem_hdr + mem_res[i])
 *   pair at the computed offset, then copies the updated header to the start
 *   of the buffer.
 *
 * @rt:                  Output buffer (may be NULL for size query).
 * @rt_size:             In/out: caller capacity on entry; required size on
 *                       exit when the buffer is too small.
 * @table:               Partially initialised resource_table (ver, num set by
 *                       the caller via DEFINE_RESOURCE_TABLE constants).
 * @mem_hdr:             fw_rsc_hdr with type = RSC_DEVMEM, shared by all
 *                       entries.
 * @mem_res:             Array of table->num fw_rsc_devmem descriptors.
 * @table_header_size:   PREFIX_RESOURCE_TABLE_HEADER_SIZE from the macro.
 * @table_size:          PREFIX_RESOURCE_TABLE_SIZE from the macro.
 */
static inline TEE_Result get_mem_rsc(struct resource_table *rt, size_t *rt_size,
				     struct resource_table *table,
				     const struct fw_rsc_hdr *mem_hdr,
				     const struct fw_rsc_devmem *mem_res,
				     size_t table_header_size,
				     size_t table_size)
{
	uint8_t *p = (uint8_t *)rt;
	uint32_t offset = 0;

	if (rt_size && *rt_size < table_size) {
		*rt_size = table_size;

		return TEE_SUCCESS;
	}

	if (!rt)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = table_header_size;

	for (size_t i = 0; i < table->num; i++, mem_res++) {
		table->offset[i] = offset;
		memcpy(p + offset, mem_hdr, sizeof(*mem_hdr));
		offset += sizeof(*mem_hdr);
		memcpy(p + offset, mem_res, sizeof(*mem_res));
		offset += sizeof(*mem_res);
	}

	memcpy(p, table, table_header_size);

	return TEE_SUCCESS;
}

#endif
