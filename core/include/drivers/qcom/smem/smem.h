/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Qualcomm Shared Memory (SMEM) - Public API
 *
 */

/*
 * =========================================================================
 * Qualcomm Shared Memory (SMEM) Framework Overview
 * =========================================================================
 *
 * SMEM is a fixed-size, physically contiguous shared memory region used as
 * the primary inter-processor communication (IPC) substrate on Qualcomm SoCs.
 * It is initialized at boot time by the boot firmware and remains accessible
 * to all participating processors for the lifetime of the system.  Each
 * processor (host) that participates in SMEM has a unique host identifier
 * and may read from or write to the portions of SMEM that it is permitted
 * to access.
 *
 * Partition Model
 * ---------------
 * SMEM data is organised into partitions of two kinds:
 *
 *   Common partition:  accessible to all hosts; holds globally shared items.
 *   Edge-pair partition:  shared between exactly two hosts; holds items
 *                         private to that host pair.
 *
 * Within each partition, items are stored in two heap regions that grow
 * toward each other: an uncached/upward region and a cached/downward region.
 *
 * NOTE: This driver supports lookup of uncached/upward items only.
 * Cached/downward item allocation and lookup are not implemented; items
 * that exist only in the cached region are not visible to this driver.
 *
 * Item Model
 * ----------
 * An SMEM item is a data blob identified by a 16-bit item ID.
 *
 * Host Identifier Model
 * ---------------------
 * Each processor is assigned a 16-bit host identifier that encodes
 * the processor type, instance, protection domain, and chiplet.
 * Two special values are reserved: QTI_SMEM_HOST_COMMON (common partition
 * access) and QTI_SMEM_HOST_INVALID (unset/error sentinel).  Host
 * identifiers must be constructed with qti_smem_host_id(), never directly.
 *
 * =========================================================================
 */

#ifndef SMEM_H
#define SMEM_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * QTI_SMEM_HOST_COMMON - pseudo-host for the common SMEM partition.
 *
 * Items in the common partition are accessible to all hosts.
 */
#define QTI_SMEM_HOST_COMMON ((uint16_t)0xfffeU)

/*
 * QTI_SMEM_HOST_INVALID - sentinel value for an invalid or unset host.
 *
 */
#define QTI_SMEM_HOST_INVALID ((uint16_t)0xffffU)

/* -----------------------------------------------------------------------
 * Processor identifier
 *
 * Pass this as the proc_id argument to qti_smem_host_id().
 * Currently only QTI_SMEM_PROC_TZ is supported.
 * -----------------------------------------------------------------------
 */
#define QTI_SMEM_PROC_TZ 7U

/* Lookup flags - currently only 0 is valid */
#define QTI_SMEM_FLAG_NONE 0U

/*
 * qti_smem_init() - Initialize the SMEM driver.
 *
 * Initializes platform-specific SMEM resources and prepares the driver.
 *
 * This function must be called once before using other SMEM APIs. Calling it
 * again after successful initialization returns TEE_ERROR_BAD_STATE without
 * modifying driver state.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if already initialized,
 * or another TEE_ERROR_* value on failure.
 */
TEE_Result qti_smem_init(void);

/*
 * qti_smem_host_id() - Construct a SMEM host identifier.
 * @proc_id:  [in]  processor ID (use QTI_SMEM_PROC_* macro)
 * @proc_num: [in]  processor instance number
 * @pd_num:   [in]  protection-domain number
 * @chiplet:  [in]  chiplet identifier
 * @host:     [out] output host identifier (must not be NULL)
 *
 * Constructs a valid SMEM host identifier from the given parameters.
 * The internal bit encoding is an implementation detail; callers must
 * use this function rather than constructing host values directly.
 *
 * Return:
 *   TEE_SUCCESS            success
 *   TEE_ERROR_BAD_PARAMETERS  @host is NULL, any parameter is out of range,
 *                             or the encoded value would collide with a
 *                             reserved host identifier
 */
TEE_Result qti_smem_host_id(uint16_t proc_id, uint16_t proc_num,
			    uint16_t pd_num, uint16_t chiplet, uint16_t *host);

/*
 * qti_smem_lookup() - Look up an existing SMEM item.
 * @remote_host: [in]  remote host for a host-pair partition, or
 *                     QTI_SMEM_HOST_COMMON for the common partition
 * @item:        [in]  SMEM item ID
 * @flags:       [in]  must be QTI_SMEM_FLAG_NONE
 * @item_ptr:    [out] pointer to item payload (must not be NULL)
 * @item_size:   [out] size of item payload in bytes (may be NULL)
 *
 * Searches the SMEM partition selected by @remote_host for an item with the
 * given item ID.
 *
 * Return:
 *   TEE_SUCCESS               success; *item_ptr points to item payload
 *   TEE_ERROR_BAD_PARAMETERS  invalid argument (@item_ptr is NULL,
 *                             @remote_host is QTI_SMEM_HOST_INVALID,
 *                             @flags is not QTI_SMEM_FLAG_NONE, or
 *                             @item >= max_items)
 *   TEE_ERROR_BAD_STATE       driver not initialized
 *   TEE_ERROR_ITEM_NOT_FOUND  item or partition not found
 *   TEE_ERROR_ACCESS_DENIED   partition not mapped or access denied
 *   TEE_ERROR_BAD_FORMAT      corrupted shared-memory metadata
 */
TEE_Result qti_smem_lookup(uint16_t remote_host, uint16_t item, uint32_t flags,
			   void **item_ptr, size_t *item_size);

#endif /* SMEM_H */
