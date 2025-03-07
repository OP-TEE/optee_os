// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023, 2025 NXP
 */
#include <assert.h>
#include <drivers/imx_mu.h>
#include <imx-regs.h>
#include <kernel/delay.h>
#include <kernel/spinlock.h>
#include <string.h>
#include <trace.h>

#include "imx_mu_platform.h"

#define RX_TIMEOUT (100 * 1000)

#if defined(CFG_MX93) || defined(CFG_MX91)
#define IS_MU_TRUST (MU_BASE == MU_TRUST_BASE)
#else
#define IS_MU_TRUST false
#endif

static unsigned int mu_spinlock = SPINLOCK_UNLOCK;

__weak void imx_mu_plat_init(vaddr_t base __unused)
{
}

__weak TEE_Result imx_mu_plat_send(vaddr_t base __unused,
				   unsigned int index __unused,
				   uint32_t msg __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

__weak TEE_Result imx_mu_plat_receive(vaddr_t base __unused,
				      unsigned int index __unused,
				      uint32_t *msg __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * Receive a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[out]msg: message received
 */
static TEE_Result imx_mu_receive_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;
	uint32_t response = 0;
	unsigned int nb_channel = 0;
	uint64_t tout_rx = timeout_init_us(RX_TIMEOUT);

	assert(base && msg);

	do {
		res = imx_mu_plat_receive(base, 0, &response);
		if (timeout_elapsed(tout_rx))
			break;
	} while (res == TEE_ERROR_NO_DATA);

	if (res)
		return res;

	memcpy(&msg->header, &response, sizeof(response));

	/* Check the size of the message to receive */
	if (msg->header.size > IMX_MU_MSG_SIZE) {
		EMSG("Size of the message is > than IMX_MU_MSG_SIZE");
		return TEE_ERROR_BAD_FORMAT;
	}

	nb_channel = imx_mu_plat_get_rx_channel(base);

	for (count = 1; count < msg->header.size; count++) {
		res = imx_mu_plat_receive(base, count % nb_channel,
					  &msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/*
 * Send a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[in]msg: message to send
 */
static TEE_Result imx_mu_send_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;
	unsigned int nb_channel = 0;
	unsigned int start_index = 0;
	unsigned int end_index = 0;
	uint32_t word = 0;

	assert(base && msg);

	if (msg->header.size > IMX_MU_MSG_SIZE) {
		EMSG("msg->size is > than IMX_MU_MSG_SIZE");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (IS_MU_TRUST) {
		/*
		 * make sure command (bit[31:26]) is higher than SCM_CR2_CMD_VAL
		 * SCM_CR2_CMD_VAL is set to 0 by ELE FW. but let’s use
		 * max value.
		 */
		word |= GENMASK_32(31, 26);

		/* size (including dummy header) ->  bit[19:16]*/
		word |= SHIFT_U32(((msg->header.size + 1) & GENMASK_32(3, 0)),
				  16);

		res = imx_mu_plat_send(base, start_index, word);
		if (res)
			return res;

		start_index++;
		memcpy(&word, &msg->header, sizeof(uint32_t));
		res = imx_mu_plat_send(base, start_index, word);
		if (res)
			return res;

		start_index++;
		/*
		 * TR15 is reserved for special USM commands
		 */
		nb_channel = imx_mu_plat_get_tx_channel(base) - 1;
		end_index = msg->header.size + 1;
		assert(end_index < nb_channel);
	} else {
		memcpy(&word, &msg->header, sizeof(uint32_t));
		res = imx_mu_plat_send(base, start_index, word);
		if (res)
			return res;

		start_index++;
		nb_channel = imx_mu_plat_get_tx_channel(base);
		end_index = msg->header.size;
	}

	for (count = start_index; count < end_index; count++) {
		res = imx_mu_plat_send(base, count % nb_channel,
				       msg->data.u32[count - start_index]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

void imx_mu_init(vaddr_t base)
{
	uint32_t exceptions = 0;

	if (!base) {
		EMSG("Bad MU base address");
		return;
	}

	exceptions = cpu_spin_lock_xsave(&mu_spinlock);

	imx_mu_plat_init(base);

	cpu_spin_unlock_xrestore(&mu_spinlock, exceptions);
}

TEE_Result imx_mu_call(vaddr_t base, struct imx_mu_msg *msg,
		       bool wait_for_answer)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;

	if (!base || !msg)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&mu_spinlock);

	res = imx_mu_send_msg(base, msg);
	if (res == TEE_SUCCESS && wait_for_answer)
		res = imx_mu_receive_msg(base, msg);

	cpu_spin_unlock_xrestore(&mu_spinlock, exceptions);

	return res;
}
