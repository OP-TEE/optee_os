/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Texas Instruments SCI Transport Protocol Header
 *
 * Copyright (C) 2018-2025 Texas Instruments Incorporated - https://www.ti.com/
 */

#ifndef TI_SCI_TRANSPORT_H
#define TI_SCI_TRANSPORT_H

#include <drivers/mailbox.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define THREAD_DIR_TX (0)
#define THREAD_DIR_RX (1)

/**
 * struct ti_sci_msg - TISCI message structure
 * @len: Length of data in the Buffer
 * @buf: Buffer pointer
 *
 * This is the structure for data used in ti_sci_transport_{send,recv}()
 */
struct ti_sci_msg {
	size_t len;
	uint8_t *buf;
};

/**
 * ti_sci_transport_send() - Send data over a TISCI transport
 * @msg: Pointer to ti_sci_msg
 *
 * This function sends a message over the TISCI transport. It is called by the
 * TISCI mailbox controller, consumers use mbox_send_sync().
 */
TEE_Result ti_sci_transport_send(const struct ti_sci_msg *msg);

/**
 * ti_sci_transport_recv() - Receive data over a TISCI transport
 * @msg: Pointer to ti_sci_msg
 *
 * This function receives a message over the TISCI transport. It is called by
 * the TISCI mailbox controller, consumers use mbox_recv_sync().
 */
TEE_Result ti_sci_transport_recv(struct ti_sci_msg *msg);

/**
 * ti_sci_transport_init() - Initialize the TISCI transport threads
 *
 * This function initializes the TISCI transport layer used for TISCI
 * communication. It is called by ti_sci_mbox_init().
 */
TEE_Result ti_sci_transport_init(void);

/**
 * ti_sci_mbox_init() - Register the TISCI mailbox controller
 * @chan: Receives the channel to exchange struct ti_sci_msg with mbox_*_sync()
 */
TEE_Result ti_sci_mbox_init(struct mbox_chan **chan);

#endif /* TI_SCI_TRANSPORT_H */
