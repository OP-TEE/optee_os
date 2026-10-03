/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026, STMicroelectronics
 */

/**
 * @file
 *
 * @brief inter-processor mailbox communication framework.
 */

#ifndef __DRIVERS_MAILBOX_DEVICE_H
#define __DRIVERS_MAILBOX_DEVICE_H

#include <compiler.h>
#include <kernel/dt_driver.h>
#include <sys/queue.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <util.h>

/**
 * MAILBOX_DT_DECLARE - Declare a Mailbox driver with a single
 * device tree compatible string.
 *
 * @__name: Mailbox driver name
 * @__compat: Compatible string
 * @__probe: Mailbox driver probe function
 */
#define MAILBOX_DT_DECLARE(__name, __compat, __probe) \
	static const struct dt_device_match __name ## _match_table[] = { \
		{ .compatible = __compat }, \
		{ } \
	}; \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = DT_DRIVER_MAILBOX, \
		.match_table = __name ## _match_table, \
		.probe = __probe, \
	}

/**
 * Capability flag definition
 *
 * The framework requires the mailbox device to signal message receptions
 * with an interrupt, hence there is no capability flag for it.
 */
enum mbox_capability {
	MBOX_TX_NOTIF = 0,
};

#define MBOX_TX_NOTIF_CAP  BIT(MBOX_TX_NOTIF)

/**
 * struct mbox_dev
 */
struct mbox_dev;

/*
 * struct mbox_ops - service functions provided by a mailbox device. These
 * operations are called by the mailbox framework to implement the service on
 * the mailbox device.
 */
struct mbox_ops {
	/**
	 * @brief Callback API to send outgoing mbox messages.
	 *
	 * @chan: Pointer to mbox channel handle.
	 * @data: Pointer to outgoing mbox message.
	 * @size: Outgoing mbox message size.
	 *
	 * @retval: TEE_ERROR_BAD_PARAMETERS for incorrect param.
	 * @retval: TEE_ERROR_BUSY if remote not ready for reception.
	 * @retval: TEE_SUCCESS if send is success.
	 */
	TEE_Result (*send)(const struct mbox_chan *chan,
			   const void *data, size_t size);

	/**
	 * @brief Callback API to get max data size.
	 *
	 * @handle: Pointer to mbox channel handle.
	 *
	 * @retval: Max data size supported by mailbox device.
	 */
	size_t (*max_data_size)(const struct mbox_chan *handle);

	/**
	 * @brief Callback API for enabling/disabling channel interrupt.
	 *
	 * @chan: Pointer to mbox channel handle.
	 * @enable: If true enable channel interrupt else disable
	 *	    channel interrupt.
	 *
	 * @retval: Return TEE_SUCCESS on success or error return code.
	 */
	TEE_Result (*channel_interrupt)(const struct mbox_chan *chan,
					bool enable);

	/**
	 * @brief Callback API for incoming mbox message command completion.
	 *
	 * @chan: Pointer to mbox channel handle.
	 *
	 * @retval: Return TEE_SUCCESS on success or error return code.
	 */
	TEE_Result (*complete)(struct mbox_chan *chan);

	/**
	 * @brief Callback API to get device capability.
	 *
	 * @priv: Pointer to mailbox device private info
	 *
	 * @retval: Channel capabilities flags
	 */
	uint32_t (*capabilities)(const void *priv);

	/**
	 * @brief Callback API to get mbox_chan
	 *
	 * Only used by mailbox devices registered with mbox_dt_register().
	 * Devices registered with mbox_register() do not need to implement
	 * this operation and bind their channel handles themselves.
	 *
	 * @priv: Pointer to mailbox device private info
	 * @pargs: Devicetree phandle arguments of the consumer "mboxes"
	 *	   specifier, cells are already decoded in @pargs->args
	 * @chan: Pointer to retrieve channel handle pointer
	 *
	 * @retval: Return TEE_SUCCESS on success or error return code.
	 */
	TEE_Result (*get_channel)(void *priv, struct dt_pargs *pargs,
				  struct mbox_chan **chan);
};

/*
 * MBOX_EVENT_RX Receive a message
 * MBOX_EVENT_TX Transmit a message
 */
enum mbox_event {
	MBOX_EVENT_RX,
	MBOX_EVENT_TX,
	MBOX_EVENT_NUM
};

/*
 * struct mbox_chan - Mailbox channel handle
 *
 * @notify: Boolean reflecting notif_id being allocated
 * @notify_id: Async notification ID used for the mailbox events or 0
 * @cb: Notification callback function
 * @cookie: Consumer data callback parameter
 * @mbox_dev: Mailbox device info
 * @lock: Lock for mailbox channel concurrent access
 * @rx_count: Counter of rx event received from device
 * @rx_done: Counter of rx event provided to channel consumer
 * @data: Pointer to data information from device
 */
struct mbox_chan {
	bool notify[MBOX_EVENT_NUM];
	uint32_t notify_id[MBOX_EVENT_NUM];
	mbox_callback_t cb[MBOX_EVENT_NUM];
	void *cookie;
	struct mbox_dev *mbox_dev;
	unsigned int lock;
	size_t rx_count;
	size_t rx_done;
	void *data;
};

/**
 * struct mbox_desc - mailbox descriptor provided by mailbox device.
 *
 * @ops: Pointer to device service ops.
 * @priv: Pointer to mailbox device private info.
 */
struct mbox_desc {
	const struct mbox_ops *ops;
	void *priv;
};

/*
 * struct mbox_dev - Mailbox device descriptor
 *
 * @phandle: Device phandle in the DT or 0
 * @caps: Device capabilities
 * @desc: Mailbox descriptor
 * @lock: Lock for mailbox device concurrent access
 * @link: Link to next mbox_dev
 */
struct mbox_dev {
	int phandle;
	uint32_t caps;
	const struct mbox_desc *desc;
	unsigned int lock;
	SLIST_ENTRY(mbox_dev) link;
};

/**
 * @brief Register a mbox device in mailbox framework.
 *
 * @mdev: Pointer to mailbox device descriptor pointer
 * @desc: Pointer to device mbox descriptor.
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 *
 * The @desc reference is used by the mailbox framework, possibly from
 * interrupt execution contexts.
 */
TEE_Result mbox_register(struct mbox_dev **mdev, const struct mbox_desc *desc);

/**
 * @brief Register a mbox device in mailbox framework.
 *
 * @fdt: Pointer to the device tree blob.
 * @nodeoffset: Device node in the device tree.
 * @desc: Pointer to device mbox descriptor.
 *
 * @retval: Return TEE_SUCCESS on success or error return code.
 *
 * The @desc reference is used by the mailbox framework, possibly from
 * interrupt execution contexts.
 */
#ifdef CFG_DT
TEE_Result mbox_dt_register(const void *fdt, int nodeoffset,
			    const struct mbox_desc *desc);
#else
static inline TEE_Result mbox_dt_register(const void *fdt __unused,
					  int nodeoffset __unused,
					  const struct mbox_desc *desc __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*CFG_DT*/

/**
 * @brief Notify mailbox framework for outgoing mbox message completion
 *
 * @handle: Pointer to mbox channel handle
 */
void mbox_tx_done(struct mbox_chan *handle);

/**
 * @brief Notify mailbox framework for incoming mbox message reception
 *
 * @handle: Pointer to mbox channel handle
 * @data: Message data pointer
 */
void mbox_rx_data(struct mbox_chan *handle, void *data);

#endif /* __DRIVERS_MAILBOX_DEVICE_H */
