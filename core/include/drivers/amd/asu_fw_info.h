/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __ASU_FW_INFO_H_
#define __ASU_FW_INFO_H_

#include <drivers/amd/asu_sharedmem.h>
#include <drivers/amd/fw_compat.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * asu_rtca_get_fw_version() - Read the ASUFW version from RTCA
 * @major: Returns the ASUFW major version
 * @minor: Returns the ASUFW minor version
 *
 * Direct RTCA memory read, no IPI communication with ASUFW required.
 *
 * Return: TEE_SUCCESS on success, or an error code if RTCA could not be
 *	   mapped.
 */
TEE_Result asu_rtca_get_fw_version(uint8_t *major, uint8_t *minor);

/*
 * asu_rtca_get_module_info() - Read a module's runtime info from RTCA
 * @module_id: ASU module ID (see ASU_MODULE_*_ID in asu_client.h)
 * @info: Returns the module's version/status/capability info
 *
 * Direct RTCA memory read, no IPI communication with ASUFW required.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS if module_id is
 *	   out of range, or another error code if RTCA could not be mapped.
 */
TEE_Result asu_rtca_get_module_info(uint32_t module_id,
				    struct asu_crypto_alg_info *info);

/*
 * asu_module_version_at_least() - Check a cached ASU module's version
 * @mod: Module info returned by fw_compat_get_module_info()
 * @min_major: Minimum required major version
 * @min_minor: Minimum required minor version (only checked when @mod's
 *	       major version equals @min_major)
 *
 * Decodes @mod->version using the ASU per-module Version field layout
 * ([31:16] = major, [15:0] = minor - see struct asu_crypto_alg_info).
 *
 * Return: true if @mod is valid and its version is at least
 *	   min_major.min_minor, false otherwise (including if @mod is NULL
 *	   or was never successfully read).
 */
bool asu_module_version_at_least(const struct fw_module_info *mod,
				 uint16_t min_major, uint16_t min_minor);

#endif /* __ASU_FW_INFO_H_ */
