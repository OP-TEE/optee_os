/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026, STMicroelectronics
 */

/**
 * @file
 *
 * @brief inter-processor mailbox communication framework.
 */

#ifndef __DRIVERS_MAILBOX_H
#define __DRIVERS_MAILBOX_H

#include <compiler.h>
#include <kernel/dt_driver.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <util.h>

/*
 * struct mbox_chan - opaque handle for a mailbox channel.
 */
struct mbox_chan;

/*
 * struct mbox_desc - mailbox descriptor provided by mailbox device.
 */
struct mbox_desc;

/**
 * @typedef mbox_callback_t
 * @brief Callback API for incoming mbox messages and outgoing mbox messages
 * completion.
 *
 * These callbacks are executed in an interrupt context. Registration of
 * callbacks is done with mbox_register_chan(),
 * mbox_dt_register_chan_by_index() or mbox_dt_register_chan_by_name().
 *
 * @cookie: Pointer to consumer private data provided during registration.
 */
typedef void (*mbox_callback_t)(void *cookie);

/**
 * @brief Register callback handlers for a mailbox channel.
 *
 * @rcv_cb: Receiver Callback API executed in an interrupt context or NULL.
 * @txc_cb: Interrupt callback for notifying reception of a transmitted
 *	    message, or NULL.
 * @cookie: Pointer to consumer data input parameter for callback.
 * @chan: Pointer to mbox chan handle.
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 *
 * If @rcv_cb is non NULL, callback is executed in interrupt context. Callback
 * can trigger an event in bottom half, a function from bottom half should call
 * API mbox_recv() (non blocking API) to consume incoming message. Callback can
 * call mbox_recv() (non blocking API to consume message). If @rcv_cb is NULL,
 * a thread can call mbox_recv() with block API parameter to consume incoming
 * message.
 *
 * If @txc_cb is non NULL, callback is executed in interrupt context. If
 * @txc_cb is NULL, a thread can call API mbox_send() with block API parameter
 * to wait till message is consumed by remote.
 *
 * A mailbox channel cannot be shared by several consumers.
 */
TEE_Result mbox_register_chan(mbox_callback_t rcv_cb,
			      mbox_callback_t txc_cb,
			      void *cookie,
			      struct mbox_chan *chan);

/**
 * @brief Get a mailbox channel and register callback handlers for it.
 *
 * @rcv_cb: Receiver Callback API executed in interrupt context.
 * @txc_cb: Transmitter Callback API executed in interrupt context.
 * @cookie: Pointer to consumer data input parameter for callback.
 * @fdt: Pointer to device tree blob.
 * @node: Device node in device tree.
 * @index: Index to select mailbox.
 * @chan: Pointer to mbox chan pointer handle.
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 *
 * If @rcv_cb is non NULL, callback is executed in interrupt context. Callback
 * can trigger an event in bottom half, a function from bottom half should call
 * API mbox_recv() (non blocking API) to consume the incoming message. Callback
 * can call mbox_recv() (non blocking API to consume the message). If @rcv_cb
 * is NULL, a thread can call mbox_recv() with block API parameter to consume
 * the incoming message.
 *
 * If @txc_cb is non NULL, callback is executed in interrupt context. If
 * @txc_cb is NULL, a thread can call API mbox_send() with block API parameter
 * to wait till message is consumed by remote.
 *
 * A mailbox channel cannot be shared by several consumers.
 */
#ifdef CFG_DT
TEE_Result mbox_dt_register_chan_by_index(mbox_callback_t rcv_cb,
					  mbox_callback_t txc_cb,
					  void *cookie,
					  const void *fdt, int node,
					  unsigned int index,
					  struct mbox_chan **chan);
#else
static inline
TEE_Result mbox_dt_register_chan_by_index(mbox_callback_t rcv_cb __unused,
					  mbox_callback_t txc_cb __unused,
					  void *cookie __unused,
					  const void *fdt __unused,
					  int node __unused,
					  unsigned int index __unused,
					  struct mbox_chan **chan __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*CFG_DT*/

/**
 * @brief Get a mailbox channel and register callback handlers for it, the
 * name of the channel is used to select the channel for the mbox consumer.
 *
 * @rcv_cb: Receiver Callback API executed in interrupt context.
 * @txc_cb: Transmitter Callback API executed in interrupt context.
 * @cookie: Pointer to consumer data input parameter for callback.
 * @fdt: Pointer to device tree blob.
 * @node: Device node in the device tree.
 * @name: Pointer to channel name.
 * @chan: Pointer to mbox chan pointer handle.
 *
 * @retval: Return TEE_SUCCESS on success or appropriate error code.
 *
 * If @rcv_cb is non NULL, callback is executed in interrupt context. Callback
 * can trigger an event in bottom half, a function from bottom half should call
 * API mbox_recv() (non blocking API) to consume the incoming message. Callback
 * can call mbox_recv() (non blocking API to consume the message). If @rcv_cb
 * is NULL, a thread can call mbox_recv() with block API parameter to consume
 * the incoming message.
 *
 * If @txc_cb is non NULL, callback is executed in interrupt context. If
 * @txc_cb is NULL, a thread can call API mbox_send() with block API parameter
 * to wait till message is consumed by remote.
 *
 * A mailbox channel cannot be shared by several consumers.
 */
#ifdef CFG_DT
TEE_Result mbox_dt_register_chan_by_name(mbox_callback_t rcv_cb,
					 mbox_callback_t txc_cb,
					 void *cookie, const void *fdt,
					 int node,
					 const char *name,
					 struct mbox_chan **chan);
#else
static inline
TEE_Result mbox_dt_register_chan_by_name(mbox_callback_t rcv_cb __unused,
					 mbox_callback_t txc_cb __unused,
					 void *cookie __unused,
					 const void *fdt __unused,
					 int node __unused,
					 const char *name __unused,
					 struct mbox_chan **chan __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*CFG_DT*/

/**
 * @brief Retrieve max data size supported by the device used by a mbox
 * consumer.
 *
 * @handle: Pointer to mbox channel handle.
 * @size: Pointer to max size of the data supported by the device.
 *
 * @retval: Return TEE_SUCCESS on success or appropriate error code.
 */
TEE_Result mbox_data_max_size(const struct mbox_chan *handle, size_t *size);

/**
 * @brief Send a message over the mbox device.
 *
 * A message is considered consumed once the remote interrupt handle finishes.
 *
 * @handle: Pointer to mbox channel handle.
 * @wait: If true, busy-wait for remote to consume the message. This requires
 *	  CFG_CORE_ASYNC_NOTIF and a device supporting transmit completion
 *	  notification, otherwise TEE_ERROR_NOT_SUPPORTED is returned. For a
 *	  handle registered with a transmit complete callback, true returns
 *	  TEE_ERROR_BAD_PARAMETERS.
 * @data: Pointer to the data sent in the message.
 * @size: Size of the data. The caller uses mbox_data_max_size() to know the
 *	  device max data size.
 *
 * @retval: TEE_ERROR_BUSY If the remote hasn't yet read the last data sent.
 * @retval: TEE_ERROR_EXCESS_DATA If size exceeds the max data size supported
 *	    by the device.
 * @retval: TEE_ERROR_BAD_PARAMETERS If there was a bad parameter.
 * @retval: TEE_SUCCESS On success.
 */
TEE_Result mbox_send(const struct mbox_chan *handle, bool wait,
		     const void *data, size_t size);

/**
 * @brief Receive a message over the mbox device.
 *
 * This API consumes the incoming message if any.
 *
 * @handle: Pointer to mbox channel handle.
 * @wait: If true, wait till a message is received. This requires
 *	  CFG_CORE_ASYNC_NOTIF, otherwise TEE_ERROR_NOT_SUPPORTED is returned.
 *	  For a handle registered with a receive callback, true returns
 *	  TEE_ERROR_BAD_PARAMETERS.
 * @data: Pointer to the data area for retrieving message content.
 * @size: Size of data to be recopied.
 *
 * @retval: TEE_ERROR_NO_DATA when no data available.
 * @retval: TEE_ERROR_BAD_PARAMETERS If error on parameters.
 * @retval: TEE_ERROR_EXCESS_DATA If size exceeds the max data size supported
 *	    by the device.
 * @retval: TEE_SUCCESS on success.
 */
TEE_Result mbox_recv(const struct mbox_chan *handle, bool wait,
		     void *data, size_t size);

#endif /* __DRIVERS_MAILBOX_H */
