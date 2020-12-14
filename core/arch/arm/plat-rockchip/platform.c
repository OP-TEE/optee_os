// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <stdint.h>

int __weak platform_secure_init(void)
{
	return 0;
}

int __weak platform_secure_ddr_region(int rgn __maybe_unused,
				      paddr_t st __maybe_unused,
				      size_t sz __maybe_unused)
{
	MSG("Not protecting region %d: 0x%lx-0x%lx\n", rgn, st, st + sz);

	return 0;
}

static TEE_Result platform_init(void)
{
	int ret = 0;

	platform_secure_init();

	/*
	 * Rockchip SoCs can protect multiple memory regions (mostly 8).
	 * Region 0 is assigned for Trusted-Firmware memory, so use
	 * regions 1 for OP-TEE memory, which leaves on all known SoCs
	 * at least 6 more regions available for other purposes.
	 */
	ret = platform_secure_ddr_region(1, CFG_TZDRAM_START, CFG_TZDRAM_SIZE);
	if (ret < 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

service_init(platform_init);
