/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 *
 */

#ifndef __TPM2_MMIO_H__
#define __TPM2_MMIO_H__

#include <mm/core_memprot.h>
#include <stdint.h>
#include <tpm2.h>

struct tpm2_mmio_data {
	struct io_pa_va base;
	struct tpm2_chip chip;
};

enum tpm2_result tpm2_mmio_init(struct tpm2_mmio_data *md, paddr_t pbase);

#endif	/* __TPM2_MMIO_H__ */

