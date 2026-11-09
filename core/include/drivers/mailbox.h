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
#include <stdint.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <util.h>

/*
 * struct mbox_chan - opaque handle for a mailbox channel.
 */
struct mbox_chan;
struct mbox_controller;

/**
 * @brief Request a mailbox channel from a specific controller.
 *
 * @controller: Mailbox controller providing the channel.
 * @args: Controller-specific channel specifier cells.
 * @args_count: Number of cells in @args.
 * @chan: Receives the requested channel handle.
 *
 * The provider defines the meaning of @args. The array is only needed for
 * this call; a provider retaining the specifier must copy it.
 *
 * A channel is granted to a single consumer until it is released with
 * mbox_free_channel().
 *
 * @retval: TEE_ERROR_BUSY if the channel is already granted.
 * @retval: TEE_SUCCESS on success.
 * @retval: Another error code on failure.
 */
TEE_Result mbox_request_channel(struct mbox_controller *controller,
				const uint32_t *args, size_t args_count,
				struct mbox_chan **chan);

/**
 * @brief Release a mailbox channel so that it can be requested again.
 *
 * @chan: Channel handle obtained with mbox_request_channel(). The handle
 *	  must not be used after the call. Releasing a channel not granted
 *	  has no effect.
 */
void mbox_free_channel(struct mbox_chan *chan);

/**
 * @brief Send a message over a mailbox channel.
 *
 * The format of @req is defined by the controller driver. The driver may
 * also report a result in @req, for instance when the send operation is a
 * request/response transaction.
 *
 * @handle: Pointer to mbox channel handle.
 * @req: Pointer to the mailbox request to send.
 *
 * @retval: TEE_ERROR_BUSY if the remote is not ready for reception.
 * @retval: TEE_ERROR_BAD_PARAMETERS if there was a bad parameter.
 * @retval: TEE_ERROR_BAD_STATE if the channel is not requested.
 * @retval: TEE_SUCCESS on success.
 * @retval: Another error code reported by the controller driver.
 */
TEE_Result mbox_send_sync(const struct mbox_chan *handle, void *req);

/**
 * @brief Receive a message over a mailbox channel.
 *
 * This API consumes the incoming message if any. The format of @req is
 * defined by the controller driver.
 *
 * @handle: Pointer to mbox channel handle.
 * @req: Pointer to the mailbox request filled with the received message.
 *
 * @retval: TEE_ERROR_NO_DATA when no message is available.
 * @retval: TEE_ERROR_NOT_SUPPORTED if the controller cannot receive.
 * @retval: TEE_ERROR_BAD_PARAMETERS if there was a bad parameter.
 * @retval: TEE_ERROR_BAD_STATE if the channel is not requested.
 * @retval: TEE_SUCCESS on success.
 * @retval: Another error code reported by the controller driver.
 */
TEE_Result mbox_recv_sync(const struct mbox_chan *handle, void *req);

#ifdef CFG_DT
/**
 * @brief Request a mailbox channel from the "mboxes" device tree property.
 *
 * @fdt: Device tree to work on.
 * @nodeoffset: Node offset of the consumer in @fdt.
 * @index: Index of the channel in the "mboxes" property.
 * @chan: Receives the channel handle on success.
 *
 * @retval: TEE_SUCCESS on success.
 * @retval: TEE_ERROR_BAD_PARAMETERS If there was a bad parameter.
 * @retval: TEE_ERROR_ITEM_NOT_FOUND If @index does not exist.
 * @retval: TEE_ERROR_DEFER_DRIVER_INIT If the controller is not yet probed.
 * @retval: TEE_ERROR_BUSY If the channel is already granted.
 * @retval: Any other error returned by the controller.
 */
TEE_Result mbox_dt_request_channel_by_index(const void *fdt, int nodeoffset,
					    unsigned int index,
					    struct mbox_chan **chan);

/**
 * @brief Request a mailbox channel from its name in "mbox-names".
 *
 * @fdt: Device tree to work on.
 * @nodeoffset: Node offset of the consumer in @fdt.
 * @name: Name of the channel in the "mbox-names" property.
 * @chan: Receives the channel handle on success.
 *
 * @retval: TEE_ERROR_ITEM_NOT_FOUND If @name is not in "mbox-names", else
 *	    same return values as mbox_dt_request_channel_by_index().
 */
TEE_Result mbox_dt_request_channel_by_name(const void *fdt, int nodeoffset,
					   const char *name,
					   struct mbox_chan **chan);
#else
static inline TEE_Result
mbox_dt_request_channel_by_index(const void *fdt __unused,
				 int nodeoffset __unused,
				 unsigned int index __unused,
				 struct mbox_chan **chan __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
mbox_dt_request_channel_by_name(const void *fdt __unused,
				int nodeoffset __unused,
				const char *name __unused,
				struct mbox_chan **chan __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DT */

#endif /* __DRIVERS_MAILBOX_H */
