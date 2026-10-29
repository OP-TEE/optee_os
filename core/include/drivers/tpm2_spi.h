/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __DRIVERS_TPM2_SPI_H__
#define __DRIVERS_TPM2_SPI_H__

#include <drivers/tpm2_chip.h>
#include <spi.h>

/*
 * Register a TPM2 chip reachable over SPI using the TCG PC Client PTP SPI
 * (TIS) protocol. The transport is built on the generic OP-TEE SPI interface
 * (struct spi_chip), so it is independent of any particular SPI controller.
 * The caller owns *chip, must have configured it (chip->ops->configure())
 * before calling this, and must keep it valid for the lifetime of the
 * registered TPM.
 */
enum tpm2_result tpm2_spi_init(struct spi_chip *chip);

#endif	/* __DRIVERS_TPM2_SPI_H__ */
