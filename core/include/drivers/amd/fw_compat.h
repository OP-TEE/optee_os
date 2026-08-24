/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __FW_COMPAT_H_
#define __FW_COMPAT_H_

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Per-module version/capability snapshot, populated once at boot by
 * fw_compat_check() and read-only afterwards. @version and @feature_caps
 * use the backend's native encoding (for ASUFW see struct
 * asu_crypto_alg_info). @valid is false if the module could not be read
 * or fw_compat_check() has not run yet.
 */
struct fw_module_info {
	uint32_t version;
	uint16_t feature_caps;
	bool valid;
};

/*
 * fw_compat_check() - Validate underlying firmware compatibility at boot
 *
 * Queries the version of each configured firmware backend and logs the
 * detected version, and validates it against the build-time configured
 * minimum (CFG_AMD_ASU_MINVER_MAJ / _MNR). On success, also reads and
 * caches every module's per-module version and feature capabilities for
 * later retrieval through fw_compat_get_module_info().
 */
void fw_compat_check(void);

/*
 * fw_compat_get_module_info() - Retrieve a module's cached version/capability
 * @module_id: Backend-specific module ID (see ASU_MODULE_*_ID for ASUFW)
 *
 * Must be called after fw_compat_check() has run (i.e. from a driver_init()
 * or later, never before the backend that owns module_id has finished
 * initializing).
 *
 * Return: Pointer to the module's cached info, or NULL if module_id is out
 *	   of range or the owning backend never successfully initialized.
 *	   Callers must still check the returned entry's "valid" field.
 */
const struct fw_module_info *fw_compat_get_module_info(uint32_t module_id);

#endif /* __FW_COMPAT_H_ */
