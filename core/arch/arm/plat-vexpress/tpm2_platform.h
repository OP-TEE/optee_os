/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 *
 */

#ifndef __TPM2_PLATFORM_H__
#define __TPM2_PLATFORM_H__

#include <drivers/tpm2_mmio.h>

#define TPM2_BASE 0x0c000000

TEE_Result test_tpm2(struct tpm2_mmio_data *md);

#endif /*__TPM2_PLATFORM_H__ */
