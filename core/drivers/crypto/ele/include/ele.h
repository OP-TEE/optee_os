/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright NXP 2025
 */

#ifndef __ELE_H_
#define __ELE_H_

#include <drivers/imx_mu.h>
#include <tee_api_types.h>
#include <trace.h>

/* Definitions for communication protocol */
#define ELE_VERSION_HSM 0x07
#define ELE_REQUEST_TAG 0x17

static inline size_t size_msg(size_t cmd)
{
	size_t words = ROUNDUP(cmd, sizeof(uint32_t)) / sizeof(uint32_t);

	/* Add the header size */
	words = words + 1;

	return words;
}

#define SIZE_MSG_32(_msg) size_msg(sizeof(_msg))

/*
 * The CRC is the last word of the message
 *
 * msg: MU message to hash
 */
void update_crc(struct imx_mu_msg *msg);

/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg MU message
 */
TEE_Result imx_ele_call(struct imx_mu_msg *msg);

#endif /* __ELE_H_ */
