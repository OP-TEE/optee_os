/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef RAMBLUR_PIMEM_CFG_H
#define RAMBLUR_PIMEM_CFG_H

#include <types_ext.h>

/* Where the pIMEM registers are, and the vault that backs the TA window */
struct ramblur_pimem_cfg {
	paddr_t reg_base;
	size_t reg_size;
	paddr_t vault_base;
	size_t vault_size;
};

/* Panics if the configuration is missing or unusable */
void ramblur_pimem_get_cfg(struct ramblur_pimem_cfg *cfg);

#endif /* RAMBLUR_PIMEM_CFG_H */
