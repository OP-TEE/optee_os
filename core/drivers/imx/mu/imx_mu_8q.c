// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>

#include "imx_mu_platform.h"

#define MU_ATR(n)     (0x0 + (n) * (4))
#define MU_ARR(n)     (0x10 + (n) * (4))
#define MU_ASR_OFFSET 0x20
#define MU_ACR_OFFSET 0x24

#define MU_SR_RF(n) SHIFT_U32(1, 27 - (n))
#define MU_SR_TE(n) SHIFT_U32(1, 23 - (n))

#define MU_CR_GIE_MASK GENMASK_32(31, 28)
#define MU_CR_RIE_MASK GENMASK_32(27, 24)
#define MU_CR_TIE_MASK GENMASK_32(23, 20)
#define MU_CR_GIR_MASK GENMASK_32(19, 16)
#define MU_CR_F_MASK   GENMASK_32(2, 0)

#define MU_MAX_CHANNEL 4

static TEE_Result mu_wait_for(vaddr_t addr, uint32_t mask)
{
	uint64_t timeout = timeout_init_us(1000);

	while (!(io_read32(addr) & mask))
		if (timeout_elapsed(timeout))
			break;

	if (io_read32(addr) & mask)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

unsigned int imx_mu_plat_get_rx_channel(vaddr_t base __unused)
{
	return MU_MAX_CHANNEL;
}

unsigned int imx_mu_plat_get_tx_channel(vaddr_t base __unused)
{
	return MU_MAX_CHANNEL;
}

void imx_mu_plat_init(vaddr_t base)
{
	io_clrbits32(base + MU_ACR_OFFSET,
		     MU_CR_GIE_MASK | MU_CR_RIE_MASK | MU_CR_TIE_MASK |
		     MU_CR_GIR_MASK | MU_CR_F_MASK);
}

TEE_Result imx_mu_plat_send(vaddr_t base, unsigned int index, uint32_t msg)
{
	assert(index < MU_MAX_CHANNEL);

	/* Wait TX register to be empty */
	if (mu_wait_for(base + MU_ASR_OFFSET, MU_SR_TE(index)))
		return TEE_ERROR_BUSY;

	/* Write message in TX register */
	io_write32(base + MU_ATR(index), msg);

	return TEE_SUCCESS;
}

TEE_Result imx_mu_plat_receive(vaddr_t base, unsigned int index, uint32_t *msg)
{
	assert(index < MU_MAX_CHANNEL);

	/* Wait RX register to be full */
	if (mu_wait_for(base + MU_ASR_OFFSET, MU_SR_RF(index)))
		return TEE_ERROR_NO_DATA;

	/* Read message in RX register */
	*msg = io_read32(base + MU_ARR(index));

	return TEE_SUCCESS;
}
