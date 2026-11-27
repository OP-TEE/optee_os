/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026, STMicroelectronics
 */

/**
 * @file
 *
 * @brief Inter-processor mailbox controller interface.
 */

#ifndef __DRIVERS_MAILBOX_CONTROLLER_H
#define __DRIVERS_MAILBOX_CONTROLLER_H

#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <util.h>

struct mbox_chan;

/* Registered mailbox controller, opaque to the controller drivers */
struct mbox_controller;

/*
 * struct mbox_controller_ops - service functions provided by a mailbox
 * controller. These operations are called by the mailbox framework to
 * implement the service on the controller.
 */
struct mbox_controller_ops {
	/**
	 * @brief Get a channel of the controller.
	 *
	 * @controller: Pointer to the mailbox controller.
	 * @args: Controller-specific channel specifier cells.
	 * @args_count: Number of cells in @args.
	 * @chan: Receives the controller-owned channel handle. The framework
	 *	  sets the controller of the channel. A channel already granted
	 *	  to a consumer is reported as TEE_ERROR_BUSY by the framework,
	 *	  without calling free_channel.
	 *
	 * @retval: TEE_ERROR_BAD_PARAMETERS for incorrect specifier.
	 * @retval: TEE_ERROR_ITEM_NOT_FOUND if no channel matches @args.
	 * @retval: TEE_SUCCESS on success.
	 */
	TEE_Result (*request_channel)(struct mbox_controller *controller,
				      const uint32_t *args, size_t args_count,
				      struct mbox_chan **chan);

	/**
	 * @brief Release a channel obtained with request_channel (optional).
	 *
	 * @chan: Pointer to mbox channel handle, not used after the call.
	 */
	void (*free_channel)(struct mbox_chan *chan);

	/**
	 * @brief Send an outgoing mailbox message (mandatory).
	 *
	 * @chan: Pointer to mbox channel handle.
	 * @req: Pointer to outgoing mbox request.
	 *
	 * @retval: TEE_ERROR_BAD_PARAMETERS for incorrect param.
	 * @retval: TEE_ERROR_BUSY if remote not ready for reception.
	 * @retval: TEE_SUCCESS if send is success.
	 */
	TEE_Result (*send_sync)(const struct mbox_chan *chan, void *req);

	/**
	 * @brief Receive an incoming mailbox message (optional).
	 *
	 * @chan: Pointer to mbox channel handle.
	 * @req: Pointer to incoming mbox request.
	 *
	 * @retval: TEE_ERROR_BAD_PARAMETERS for incorrect param.
	 * @retval: TEE_ERROR_NO_DATA if no message is available.
	 * @retval: TEE_SUCCESS if receive is success.
	 */
	TEE_Result (*recv_sync)(const struct mbox_chan *chan, void *req);
};

/*
 * struct mbox_chan - Mailbox channel handle
 *
 * @controller: Mailbox controller owning the channel, set by the framework
 *	      when the channel is requested
 * @lock: Protects @requested
 * @requested: Channel granted to a consumer, managed by the framework
 */
struct mbox_chan {
	struct mbox_controller *controller;
	unsigned int lock;
	bool requested;
};

/**
 * struct mbox_controller_desc - descriptor provided by a mailbox controller.
 *
 * @ops: Pointer to controller service operations.
 * @priv: Pointer to mailbox controller private info.
 */
struct mbox_controller_desc {
	const struct mbox_controller_ops *ops;
	void *priv;
};

/**
 * @brief Register a mailbox controller in the framework.
 *
 * @controller: Receives the registered controller.
 * @desc: Pointer to mailbox controller descriptor.
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 *
 * The @desc reference is used by the mailbox framework, possibly from
 * interrupt execution contexts.
 */
TEE_Result mbox_controller_register(struct mbox_controller **controller,
				    const struct mbox_controller_desc *desc);

/**
 * @brief Get the private data of a mailbox controller.
 *
 * @controller: Controller given to the request_channel operation.
 *
 * @retval: The @priv pointer of the descriptor given at registration.
 */
void *mbox_controller_get_priv(const struct mbox_controller *controller);
#ifdef CFG_DT
/**
 * @brief Register a mailbox controller as a device tree provider.
 *
 * Create the controller as mbox_controller_register() does and make it
 * available to consumers through the "mboxes" property, using
 * mbox_dt_request_channel_by_index() or mbox_dt_request_channel_by_name().
 * The specifier cells of the "mboxes" property are given to the controller
 * request_channel operation. A driver handling several device tree nodes
 * calls this function once per node, with a descriptor per node.
 *
 * @fdt: Device tree to work on.
 * @nodeoffset: Node offset of the controller in @fdt.
 * @desc: Pointer to mailbox controller descriptor, see
 *	  mbox_controller_register().
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 */
TEE_Result mbox_dt_register_controller(const void *fdt, int nodeoffset,
				       const struct mbox_controller_desc *desc);
#else
static inline TEE_Result
mbox_dt_register_controller(const void *fdt __unused, int nodeoffset __unused,
			    const struct mbox_controller_desc *desc __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DT */

#endif /* __DRIVERS_MAILBOX_CONTROLLER_H */
