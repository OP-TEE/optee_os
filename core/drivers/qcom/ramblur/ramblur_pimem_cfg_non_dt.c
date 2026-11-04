// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/ramblur/v3/ramblur_pimem_hwio.h>
#include <platform_config.h>
#include "ramblur_pimem_cfg.h"

/* TA RAM is the pIMEM window over the vault */
static_assert(RAMBLUR_PIMEM_VAULT_TA_SIZE == CFG_TA_RAM_VA_SIZE);

void ramblur_pimem_get_cfg(struct ramblur_pimem_cfg *cfg)
{
	cfg->reg_base = RAMBLUR_PIMEM_REG_BASE;
	cfg->reg_size = RAMBLUR_PIMEM_REG_SIZE;
	cfg->vault_base = RAMBLUR_PIMEM_VAULT_TA_BASE;
	cfg->vault_size = RAMBLUR_PIMEM_VAULT_TA_SIZE;
}
