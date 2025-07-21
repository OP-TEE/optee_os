// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>

#include "imx_mu_platform.h"

#define MU_PAR 0x004
#define MU_TCR		  0x120
#define MU_TSR		  0x124
#define MU_RCR		  0x128
#define MU_RSR		  0x12C
#define MU_TR(n)	  (0x200 + 0x4 * (n))
#define MU_RR(n)	  (0x280 + 0x4 * (n))
#define MU_TSR_TE(n)	  BIT32(n)
#define MU_RSR_RF(n)	  BIT32(n)

#define RR_NUM_MASK GENMASK_32(15, 8)
#define RR_NUM_SHIFT 8
#define TR_NUM_MASK GENMASK_32(7, 0)

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

unsigned int imx_mu_plat_get_rx_channel(vaddr_t base)
{
	return (io_read32(base + MU_PAR) & RR_NUM_MASK) >> RR_NUM_SHIFT;
}

unsigned int imx_mu_plat_get_tx_channel(vaddr_t base)
{
	return io_read32(base + MU_PAR) & TR_NUM_MASK;
}

TEE_Result imx_mu_plat_send(vaddr_t base, unsigned int index, uint32_t msg)
{
	assert(index < imx_mu_plat_get_tx_channel(base));

	/* Wait TX register to be empty */
	if (mu_wait_for(base + MU_TSR, MU_TSR_TE(index)))
		return TEE_ERROR_BUSY;

	io_write32(base + MU_TR(index), msg);

	return TEE_SUCCESS;
}

TEE_Result imx_mu_plat_receive(vaddr_t base, unsigned int index, uint32_t *msg)
{
	assert(index < imx_mu_plat_get_rx_channel(base));

	/* Wait RX register to be full */
	if (mu_wait_for(base + MU_RSR, MU_RSR_RF(index)))
		return TEE_ERROR_NO_DATA;

	*msg = io_read32(base + MU_RR(index));

	return TEE_SUCCESS;
}

void imx_mu_plat_init(vaddr_t base)
{
	/* Reset status registers */
	io_write32(base + MU_TCR, 0x0);
	io_write32(base + MU_RCR, 0x0);
}
