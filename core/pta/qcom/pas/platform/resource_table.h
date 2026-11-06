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
 * A subsystem lists its regions as an array of struct fw_rsc_devmem in its
 * struct qcom_pas_ops; the PAS core serialises the table from it.
 */

#ifndef RESOURCE_TABLE_H
#define RESOURCE_TABLE_H

#include <compiler.h>
#include <stdint.h>
#include <util.h>

/*
 * resource_table : top-level header of the firmware resource table.
 *
 * @ver:      Table version; must be 1.
 * @num:      Number of resource entries (length of the offset[] array).
 * @reserved: Must be zero.
 * @offset:   Array of byte offsets from the start of the table to each
 *            fw_rsc_hdr entry.
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

#endif
