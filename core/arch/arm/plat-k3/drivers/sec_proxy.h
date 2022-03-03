/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Texas Instruments K3 Secure Proxy Driver
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#ifndef SEC_PROXY_H
#define SEC_PROXY_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define SEC_PROXY_MAX_MSG_SIZE 60

/**
 * struct k3_sec_proxy_msg - Secure proxy message structure
 * @len: Length of data in the Buffer
 * @buf: Buffer pointer
 *
 * This is the structure for data used in k3_sec_proxy_{send,recv}()
 */
struct k3_sec_proxy_msg {
	size_t len;
	uint8_t *buf;
};

/**
 * k3_sec_proxy_send() - Send data over a Secure Proxy thread
 * @msg: Pointer to k3_sec_proxy_msg
 */
TEE_Result k3_sec_proxy_send(const struct k3_sec_proxy_msg *msg);

/**
 * k3_sec_proxy_recv() - Receive data from a Secure Proxy thread
 * @msg: Pointer to k3_sec_proxy_msg
 */
TEE_Result k3_sec_proxy_recv(struct k3_sec_proxy_msg *msg);

/**
 * k3_sec_proxy_init() - Initialize the secure proxy threads
 */
TEE_Result k3_sec_proxy_init(void);

#endif /* __SEC_PROXY_H */
