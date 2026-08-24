// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <drivers/amd/fw_compat.h>
#include <inttypes.h>
#include <kernel/panic.h>
#include <trace.h>
#include <util.h>

#ifdef CFG_AMD_ASU_SUPPORT
#include <drivers/amd/asu_fw_info.h>

static struct fw_module_info asu_modules[ASU_RTCA_MODULE_COUNT];

/*
 * asu_fw_compat_probe() - Validate the ASUFW version and cache per-module
 * version/capability info
 *
 * Return: TEE_SUCCESS if the ASUFW version is at least
 *	   CFG_AMD_ASU_MINVER_MAJ/_MNR.
 */
static TEE_Result asu_fw_compat_probe(void)
{
	struct asu_crypto_alg_info info = { };
	uint32_t min_version = 0;
	uint32_t version = 0;
	uint8_t major = 0;
	uint8_t minor = 0;
	uint32_t i = 0;

	if (asu_rtca_get_fw_version(&major, &minor) != TEE_SUCCESS) {
		EMSG("Failed to read ASUFW version from RTCA");
		return TEE_ERROR_GENERIC;
	}

	IMSG("ASUFW version: %"PRIu8".%"PRIu8, major, minor);

	/*
	 * Compare as a single packed value rather than "major < MAJ ||
	 * (major == MAJ && minor < MNR)" - with the default MNR of 0 that
	 * form compares an unsigned byte against 0 with "<", which is
	 * always false and trips -Wtype-limits.
	 */
	version = SHIFT_U32(major, 8) | minor;
	min_version = SHIFT_U32(CFG_AMD_ASU_MINVER_MAJ, 8) |
		      CFG_AMD_ASU_MINVER_MNR;

	if (version < min_version) {
		EMSG("ASUFW version %"PRIu8".%"PRIu8" older than minimum %u.%u",
		     major, minor, CFG_AMD_ASU_MINVER_MAJ,
		     CFG_AMD_ASU_MINVER_MNR);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	for (i = 0; i < ASU_RTCA_MODULE_COUNT; i++) {
		if (asu_rtca_get_module_info(i, &info) != TEE_SUCCESS) {
			EMSG("Failed to read ASU module %"PRIu32" info", i);
			continue;
		}

		asu_modules[i].version = info.version;
		asu_modules[i].feature_caps = info.feature_caps;
		asu_modules[i].valid = true;

		IMSG("ASU module %"PRIu32": version=%#"PRIx32" caps=%#"PRIx16,
		     i, info.version, info.feature_caps);
	}

	return TEE_SUCCESS;
}

const struct fw_module_info *fw_compat_get_module_info(uint32_t module_id)
{
	if (module_id >= ASU_RTCA_MODULE_COUNT)
		return NULL;

	return &asu_modules[module_id];
}
#else
static TEE_Result asu_fw_compat_probe(void)
{
	return TEE_SUCCESS;
}

const struct fw_module_info *
fw_compat_get_module_info(uint32_t module_id __unused)
{
	return NULL;
}
#endif /* CFG_AMD_ASU_SUPPORT */

void fw_compat_check(void)
{
	if (asu_fw_compat_probe() != TEE_SUCCESS)
		panic("Incompatible ASUFW version");
}
