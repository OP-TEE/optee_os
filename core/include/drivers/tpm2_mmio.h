/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __DRIVERS_TPM2_MMIO_H__
#define __DRIVERS_TPM2_MMIO_H__

#include <drivers/tpm2_chip.h>
#include <mm/core_memprot.h>

enum tpm2_result tpm2_mmio_init(paddr_t pbase);

#endif	/* __DRIVERS_TPM2_MMIO_H__ */

