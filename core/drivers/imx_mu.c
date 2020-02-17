// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020-2021 NXP
 */
#include <drivers/imx_mu.h>
#include <io.h>
#include <kernel/delay.h>
#include <tee_api_types.h>

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

static TEE_Result mu_wait_for(vaddr_t addr, uint32_t mask)
{
	uint64_t timeout = timeout_init_us(1000);

	while (!(io_read32(addr) & mask)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

void mu_init(vaddr_t base)
{
	io_clrbits32(base + MU_ACR_OFFSET, MU_CR_GIE_MASK | MU_CR_RIE_MASK |
					   MU_CR_TIE_MASK | MU_CR_GIR_MASK |
					   MU_CR_F_MASK);
}

TEE_Result mu_send_msg(vaddr_t base, unsigned int index, uint32_t msg)
{
	/* Wait TX register to be empty */
	if (mu_wait_for(base + MU_ASR_OFFSET, MU_SR_TE(index)))
		return TEE_ERROR_BUSY;

	/* Write message in TX register */
	io_write32(base + MU_ATR(index), msg);

	return TEE_SUCCESS;
}

TEE_Result mu_receive_msg(vaddr_t base, unsigned int index, uint32_t *msg)
{
	/* Wait RX register to be full */
	if (mu_wait_for(base + MU_ASR_OFFSET, MU_SR_RF(index)))
		return TEE_ERROR_BUSY;

	*msg = io_read32(base + MU_ARR(index));

	return TEE_SUCCESS;
}
