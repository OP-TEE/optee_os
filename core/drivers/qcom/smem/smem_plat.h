/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Qualcomm Shared Memory (SMEM) - Internal platform abstraction interface
 *
 */

#ifndef SMEM_PLAT_H
#define SMEM_PLAT_H

#include <tee_api_defines.h>
#include <stddef.h>
#include <stdint.h>
#include <trace.h>
#include "drivers/qcom/smem/smem.h"
#include "target_config.h"

/* -----------------------------------------------------------------------
 * Mapping attribute flags passed to qti_smem_plat_map().
 * -----------------------------------------------------------------------
 */

/* QTI_SMEM_PLAT_MAP_RO - install a read-only mapping. */
#define QTI_SMEM_PLAT_MAP_RO 0x1U

/* QTI_SMEM_PLAT_MAP_RW - install a read-write mapping. */
#define QTI_SMEM_PLAT_MAP_RW 0x2U

/* -----------------------------------------------------------------------
 * Platform target information
 * -----------------------------------------------------------------------
 */

/*
 * struct qti_smem_plat_info - platform-supplied SMEM target parameters.
 * @local_host: SMEM host ID of the processor running this driver instance.
 *              Must be constructed with qti_smem_host_id().
 * @max_items:  Maximum item index the driver will accept (exclusive upper
 *              bound for the @item argument to qti_smem_lookup()).
 * @smem_size:  Total size of the SMEM region in bytes.
 *
 */
struct qti_smem_plat_info {
	uint16_t local_host;
	uint16_t max_items;
	size_t smem_size;
};

/* -----------------------------------------------------------------------
 * Platform operation interface
 *
 * Implemented once per platform in qti_smem_plat_xxx.c.
 * The common core calls these; it does not know PA/VA/MMU details.
 * -----------------------------------------------------------------------
 */

/*
 * qti_smem_plat_init() - Platform entry point for SMEM initialization.
 * @plat_info: caller-allocated struct to fill with platform parameters.
 *
 * Discovers SMEM target parameters (size, max_items, local host)
 * from WONCE registers or device tree and writes them into @plat_info.
 *
 * PA base and VA base are stored in platform-private state only.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS if @plat_info is
 * NULL, TEE_ERROR_NOT_SUPPORTED if target info is unavailable,
 * TEE_ERROR_BAD_FORMAT if target info is corrupted.
 */
TEE_Result qti_smem_plat_init(struct qti_smem_plat_info *plat_info);

/*
 * qti_smem_plat_map() - Map a region of SMEM into the virtual address space.
 * @offset: byte offset from the SMEM physical base (not PA, not VA).
 * @size:   number of bytes to map.
 * @flags:  QTI_SMEM_PLAT_MAP_RO or QTI_SMEM_PLAT_MAP_RW.
 *
 * Must validate that offset + size does not exceed smem_size.
 * Mapping is ignored because SMEM is statically mapped.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS on failure.
 */
TEE_Result qti_smem_plat_map(uint32_t offset, size_t size, uint32_t flags);

/*
 * qti_smem_plat_get_addr() - Translate an SMEM offset to a virtual address.
 * @offset: byte offset from the SMEM physical base.
 *
 * Returns the virtual address corresponding to the given offset within
 * the statically mapped SMEM region (1:1 PA/VA mapping).
 *
 * Return: virtual address on success, NULL if the offset is out of range.
 */
void *qti_smem_plat_get_addr(uint32_t offset);

#endif /* SMEM_PLAT_H */
