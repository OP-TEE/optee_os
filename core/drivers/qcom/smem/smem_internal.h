/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Qualcomm Shared Memory (SMEM) - Internal definitions
 *
 * This header is private to the SMEM driver implementation.
 * It must NOT be included by any code outside of the qti_smem driver.
 */

#ifndef SMEM_INTERNAL_H
#define SMEM_INTERNAL_H

#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <util.h>
#include "drivers/qcom/smem/smem.h"

/* -----------------------------------------------------------------------
 * Protocol constants
 * -----------------------------------------------------------------------
 */

/*
 * BOOT info page: the first 4096 bytes of SMEM contain BOOT/static
 * version metadata.  This page is mapped read-only during init.
 *
 * Layout of the first 4096 bytes:
 *   [0,   64): proc_comm[16]  - legacy IPC mechanism (16 x uint32_t)
 *   [64, 192): ver[32]        - version array (32 x uint32_t)
 *   [192, 4096): ...          - other static metadata
 *
 * The BOOT SMEM version is at ver[QTI_SMEM_VERSION_BOOT_OFFSET].
 */
#define QTI_SMEM_BOOT_INFO_SIZE U(4096)

/* TOC page size: the TOC occupies the last 4096 bytes of SMEM. */
#define QTI_SMEM_TOC_SIZE U(4096)

/* Supported TOC version. */
#define QTI_SMEM_TOC_VERSION U(1)

/* Maximum number of TOC entries processed (bounds the TOC walk). */
#define QTI_SMEM_TOC_MAX_ENTRIES U(40)

/*
 * TOC magic: "$TOC" stored as a little-endian uint32_t.
 *   '$' = 0x24, 'T' = 0x54, 'O' = 0x4F, 'C' = 0x43
 */
#define QTI_SMEM_TOC_MAGIC U(0x434F5424)

/*
 * Partition magic: "$PRT" stored as a little-endian uint32_t.
 *   '$' = 0x24, 'P' = 0x50, 'R' = 0x52, 'T' = 0x54
 */
#define QTI_SMEM_PART_MAGIC U(0x54525024)

/** Canary value stored in every item header. */
#define QTI_SMEM_ITEM_CANARY U(0xa5a5)

/*
 * BOOT SMEM version constants.
 *
 * The BOOT SMEM version word is stored at index QTI_SMEM_VERSION_BOOT_OFFSET
 * within the ver[] array of struct qti_smem_static_header.
 *
 * Version word format:
 *   bits [31:16] = major version
 *   bits [15:0]  = minor version
 *
 * This driver supports major version 0x000C (12).
 * Minor version differences are accepted if the layout is compatible.
 */
#define QTI_SMEM_VERSION_ID U(0x000C0001)
#define QTI_SMEM_MAJOR_VERSION_MASK U(0xffff0000)
#define QTI_SMEM_MINOR_VERSION_MASK U(0x0000ffff)
#define QTI_SMEM_VERSION_BOOT_OFFSET U(7)

/*
 * Internal multi-host partition marker.
 * A TOC entry with host0 == host1 == QTI_SMEM_HOST_MULTIHOST describes
 * a multi-host partition whose membership is encoded in hosts_bitmap.
 * Not exposed publicly.
 */
#define QTI_SMEM_HOST_MULTIHOST U(0xfffc)

/* -----------------------------------------------------------------------
 * Host-ID encoding
 *
 * A regular host ID is a 16-bit value encoded as:
 *
 *   bits [5:0]   proc_id   (6 bits, values 0-63)
 *   bits [9:6]   proc_num  (4 bits, values 0-15)
 *   bits [12:10] pd_num    (3 bits, values 0-7)
 *   bits [15:13] chiplet   (3 bits, values 0-7)
 *
 * Special values that must never be produced by qti_smem_host_id():
 *   QTI_SMEM_HOST_COMMON    = 0xfffe
 *   QTI_SMEM_HOST_INVALID   = 0xffff
 *   QTI_SMEM_HOST_MULTIHOST = 0xfffc
 * -----------------------------------------------------------------------
 */

#define HOST_PROC_ID_BITS U(6)
#define HOST_PROC_NUM_BITS U(4)
#define HOST_PD_NUM_BITS U(3)
#define HOST_CHIPLET_BITS U(3)

#define HOST_PROC_ID_SHIFT U(0)
#define HOST_PROC_NUM_SHIFT U(6)
#define HOST_PD_NUM_SHIFT U(10)
#define HOST_CHIPLET_SHIFT U(13)

#define HOST_PROC_ID_MASK (BIT32(HOST_PROC_ID_BITS) - 1)
#define HOST_PROC_NUM_MASK (BIT32(HOST_PROC_NUM_BITS) - 1)
#define HOST_PD_NUM_MASK (BIT32(HOST_PD_NUM_BITS) - 1)
#define HOST_CHIPLET_MASK (BIT32(HOST_CHIPLET_BITS) - 1)

/* -----------------------------------------------------------------------
 * Shared-memory ABI structures
 *
 * These structures represent the fixed binary layout of the SMEM protocol.
 * They are internal to the SMEM driver and must NOT be exposed in any
 * public header.
 * -----------------------------------------------------------------------
 */

/*
 * struct qti_smem_static_header - layout of the first 4096 bytes of SMEM.
 *
 * The ver[] array at offset 64 contains version words for each SMEM
 * subsystem.  Index QTI_SMEM_VERSION_BOOT_OFFSET (7) holds the BOOT
 * SMEM version that this driver validates during init.
 */
struct qti_smem_static_header {
	uint32_t proc_comm[16]; /* legacy IPC: 16 x uint32_t = 64 bytes    */
	uint32_t ver[32]; /* version array: 32 x uint32_t = 128 bytes */
} __packed;

/*
 * struct qti_smem_toc_header - SMEM partition table (TOC) header.
 *
 * Located at: smem_base + smem_size - QTI_SMEM_TOC_SIZE
 * Immediately followed by an array of qti_smem_toc_entry records.
 */
struct qti_smem_toc_header {
	uint32_t magic; /* must equal QTI_SMEM_TOC_MAGIC              */
	uint32_t version; /* must equal QTI_SMEM_TOC_VERSION            */
	uint32_t num_entries; /* number of valid qti_smem_toc_entry records */
	uint32_t minor_version; /* informational minor version */
	uint32_t reserved[4]; /* reserved; not validated                     */
} __packed;

/*
 * struct qti_smem_toc_entry - one entry in the SMEM partition table.
 *
 * Entries follow the qti_smem_toc_header immediately in memory.
 * host0 and host1 use uint16_t to match the SMEM wire format.
 * The ABI layout must remain stable.
 */
struct qti_smem_toc_entry {
	uint32_t offset; /* byte offset of partition from SMEM base  */
	uint32_t size; /* partition size in bytes                  */
	uint32_t flags; /* reserved flags                           */
	uint16_t host0; /* first host identifier (wire uint16)      */
	uint16_t host1; /* second host identifier (wire uint16)     */
	uint32_t size_cacheline; /* cached-item alignment (0 = default)      */
	uint32_t reserved[3]; /* reserved; not validated                  */
	uint32_t exclusion_sizes[4]; /* per-host exclusion sizes */
} __packed;

/*
 * struct qti_smem_partition_header - header at the start of each partition.
 *
 * host0 and host1 use uint16_t to match the SMEM wire format.
 * The ABI layout must remain stable.
 *
 * offset_free_uncached: end of the allocated uncached (upward) region.
 *   Grows upward from sizeof(partition_header).
 * offset_free_cached: start of the allocated cached (downward) region.
 *   Grows downward from partition size.
 */
struct qti_smem_partition_header {
	uint32_t magic; /* must equal QTI_SMEM_PART_MAGIC      */
	uint16_t host0; /* first host identifier (wire uint16)  */
	uint16_t host1; /* second host identifier (wire uint16) */
	uint32_t size; /* total partition size in bytes        */
	uint32_t offset_free_uncached; /* end of uncached region */
	uint32_t offset_free_cached; /* start of allocated cached region     */
	uint32_t reserved[3]; /* reserved; not validated              */
} __packed;

/*
 * struct qti_smem_item_header - header preceding each allocated SMEM item.
 *
 * Uncached item layout (growing upward from partition header):
 *   [qti_smem_item_header][padding_header bytes][data][padding_data bytes]
 *
 * Data address:  ptr + sizeof(header) + padding_header
 * Data size:     size - padding_data
 * Next header:   ptr + sizeof(header) + padding_header + size
 */
struct qti_smem_item_header {
	uint16_t canary; /* must equal QTI_SMEM_ITEM_CANARY (0xa5a5) */
	uint16_t item; /* SMEM item identifier                       */
	uint32_t size; /* total rounded size including padding_data  */
	uint16_t padding_data; /* unused bytes at end of data region         */
	uint16_t padding_header; /* alignment gap before data */
	uint32_t reserved; /* reserved; not validated                    */
} __packed;

/* Compile-time size assertions - catch layout regressions immediately. */
static_assert(sizeof(struct qti_smem_static_header) == 192,
	      "qti_smem_static_header size mismatch");
static_assert(sizeof(struct qti_smem_toc_header) == 32,
	      "qti_smem_toc_header size mismatch");
static_assert(sizeof(struct qti_smem_toc_entry) == 48,
	      "qti_smem_toc_entry size mismatch");
static_assert(sizeof(struct qti_smem_partition_header) == 32,
	      "qti_smem_partition_header size mismatch");
static_assert(sizeof(struct qti_smem_item_header) == 16,
	      "qti_smem_item_header size mismatch");

/* -----------------------------------------------------------------------
 * Driver state
 * -----------------------------------------------------------------------
 */

/*
 * struct qti_smem_info - driver state.
 *
 */
struct qti_smem_info {
	int initialized; /* 0 = uninitialized, 1 = initialized */
	uint16_t local_host; /* local host ID                      */
	uint16_t max_items; /* maximum item ID (exclusive)        */
	uint32_t smem_size; /* total SMEM size in bytes           */
	uint32_t toc_offset; /* byte offset of TOC from SMEM base  */
	uint32_t num_toc_entries; /* validated TOC entry count          */
	uint32_t common_part_offset; /* common partition offset            */
	uint32_t common_part_size; /* common partition size              */
};

#endif /* SMEM_INTERNAL_H */
