// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Aspeed Technology Inc.
 */
#include <config.h>
#include <platform_config.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>

#include "hace_ast2600.h"

#define SCU_RST1		0x40
#define SCU_RSTCLR1		0x44
#define SCU_RST_CRYPTO		BIT(4)

#define SCU_CLKGATE1		0x80
#define SCU_CLKGATECLR1		0x84
#define SCU_CLKGATE_HACE	BIT(13)

static TEE_Result crypto_ast2600_init(void)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	vaddr_t scu_virt = 0;

	scu_virt = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_NSEC, SMALL_PAGE_SIZE);
	if (!scu_virt)
		panic();

	/* ast2600 crypto engines share the same reset control */
	io_write32(scu_virt + SCU_RST1, SCU_RST_CRYPTO);
	udelay(100);
	io_write32(scu_virt + SCU_RSTCLR1, SCU_RST_CRYPTO);

	if (IS_ENABLED(CFG_CRYPTO_DRV_HASH)) {
		io_write32(scu_virt + SCU_CLKGATECLR1, SCU_CLKGATE_HACE);

		rc = ast2600_drvcrypt_register_hash();
		if (rc) {
			EMSG("cannot register hash driver, rc=%d", rc);
			return rc;
		}
	}

	return TEE_SUCCESS;
}

early_init_late(crypto_ast2600_init);
