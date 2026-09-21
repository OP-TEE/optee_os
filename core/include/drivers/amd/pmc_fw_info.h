/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __PMC_FW_INFO_H__
#define __PMC_FW_INFO_H__

#include <stdint.h>
#include <tee_api_types.h>

/*
 * pmc_rtca_get_version() - Read the PLM version from RTCA
 * @major: Returns the PLM major version
 * @minor: Returns the PLM minor version
 *
 * Direct RTCA memory read, no IPI communication required.
 *
 * Return: TEE_SUCCESS, or an error code if RTCA could not be mapped.
 */
TEE_Result pmc_rtca_get_version(uint8_t *major, uint8_t *minor);

/*
 * pmc_fw_compat_check() - Validate the PLM version against the configured
 * minimum
 *
 * PMC is present on every board, so this check is unconditional
 * and independently triggered via its own service_init().
 * Panics on an incompatible version
 * (below CFG_AMD_PMC_MINVER_MAJ / _MNR); never returns in that case.
 */
void pmc_fw_compat_check(void);

#endif /* __PMC_FW_INFO_H__ */
