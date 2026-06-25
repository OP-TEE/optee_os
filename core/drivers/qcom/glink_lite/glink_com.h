/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __GLINK_COM_H
#define __GLINK_COM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>

#define GLINK_CFG_MAX_REMOTE_HOSTS  1
#define GLINK_CFG_MAX_NOTIFY_CBS    1

enum glink_err_type {
	GLINK_STATUS_SUCCESS = 0,
	GLINK_STATUS_INVALID_PARAM = -1,
	GLINK_STATUS_NOT_INIT = -2,
	GLINK_STATUS_OUT_OF_RESOURCES = -3,
	GLINK_STATUS_CH_TX_BUSY = -4,
	GLINK_STATUS_CH_NOT_FULLY_OPENED = -5,
	GLINK_STATUS_FAILURE = -32,
};

enum glink_link_state_type {
	GLINK_LINK_STATE_UP = 0,
	GLINK_LINK_STATE_DOWN = 1,
};

enum glink_channel_event_type {
	GLINK_CONNECTED = 0,
	GLINK_LOCAL_DISCONNECTED = 1,
	GLINK_REMOTE_DISCONNECTED = 2,
};

/* Opaque handles, private to the GLink core */
struct glink_channel_ctx;
struct glink_link_notify;

struct glink_link_info {
	const char *remote_ss;
	enum glink_link_state_type link_state;
};

typedef void (*glink_rx_notification_cb)(struct glink_channel_ctx *handle,
					 const void *priv,
					 const void *pkt_priv,
					 const void *ptr,
					 size_t size,
					 size_t intent_used);

typedef void (*glink_tx_notification_cb)(struct glink_channel_ctx *handle,
					 const void *priv,
					 const void *pkt_priv,
					 const void *ptr,
					 size_t size);

typedef void (*glink_state_notification_cb)(struct glink_channel_ctx *handle,
			const void *priv,
			enum glink_channel_event_type event);

typedef void (*glink_notify_tx_abort_cb)(struct glink_channel_ctx *handle,
					 const void *priv,
					 const void *pkt_priv);

typedef void (*glink_link_state_notif_cb)(struct glink_link_info *link_info,
					  void *priv);

struct glink_open_config {
	const char *remote_ss;
	const char *name;
	const void *priv;
	glink_rx_notification_cb notify_rx;
	glink_tx_notification_cb notify_tx_done;
	glink_state_notification_cb notify_state;
	glink_notify_tx_abort_cb notify_tx_abort;
};

struct glink_link_id {
	const char *remote_ss;
	glink_link_state_notif_cb link_notifier;
	struct glink_link_notify *handle;
};

static inline void glink_link_id_struct_init(struct glink_link_id *link_id)
{
	link_id->remote_ss = NULL;
	link_id->link_notifier = NULL;
	link_id->handle = NULL;
}

void glink_init(void);

enum glink_err_type glink_open(const struct glink_open_config *cfg_ptr,
			       struct glink_channel_ctx **handle);

enum glink_err_type glink_close(struct glink_channel_ctx *handle);

/* @options is currently unused and reserved for future flags */
enum glink_err_type glink_tx(struct glink_channel_ctx *handle,
			     const void *pkt_priv,
			     const void *data,
			     size_t size,
			     uint32_t options);

/* @reuse requests the transport to keep the receive intent for reuse */
enum glink_err_type glink_rx_done(struct glink_channel_ctx *handle,
				  const void *ptr,
				  bool reuse);

enum glink_err_type
glink_register_link_state_cb(struct glink_link_id *link_id, void *priv);

enum glink_err_type
glink_deregister_link_state_cb(struct glink_link_notify *handle);

#endif /* __GLINK_COM_H */
