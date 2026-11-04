/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef RAMBLUR_PIMEM_V3_H
#define RAMBLUR_PIMEM_V3_H

#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Set up the TA window of the controller whose registers are mapped at @regs,
 * over the vault of @size bytes at @vault. Panics if it cannot be set up.
 */
TEE_Result ramblur_pimem_v3_init(vaddr_t regs, paddr_t vault, size_t size);

#endif /* RAMBLUR_PIMEM_V3_H */
