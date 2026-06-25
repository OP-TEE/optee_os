/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __GLINK_XPORT_H
#define __GLINK_XPORT_H

#include "glink_com.h"

struct glink_transport_if;

struct glink_core_tx_pkt {
	const void *data;
	const void *pkt_priv;
	size_t size;
	size_t size_remaining;
};

struct glink_core_rx_pkt {
	const void *data;
	size_t size;
};

struct glink_channel_ctx {
	const char *remote_ss;
	const char *ch_name;
	const void *priv;
	glink_rx_notification_cb notify_rx;
	glink_tx_notification_cb notify_tx_done;
	glink_state_notification_cb notify_state;
	glink_notify_tx_abort_cb notify_tx_abort;
	struct glink_core_tx_pkt tx_pkt;
	struct glink_core_rx_pkt rx_pkt;
	struct glink_transport_if *if_ptr;
};

enum glink_transport_status {
	GLINK_XPORT_LINK_DOWN = 0,
	GLINK_XPORT_LINK_UP = 1,
};

struct glink_core_xport_ctx {
	unsigned int cs;
	enum glink_transport_status status;
	struct glink_channel_ctx ch_ctx;
};

typedef enum glink_err_type (*tx_cmd_ch_open_fn)(struct glink_transport_if
						 *if_ptr);
typedef enum glink_err_type (*tx_cmd_ch_close_fn)(struct glink_transport_if
						  *if_ptr);
typedef enum glink_err_type (*tx_cmd_local_rx_done_fn)(struct glink_transport_if
						       *if_ptr,
						       const void *ptr);
typedef enum glink_err_type (*tx_data_fn)(struct glink_transport_if *if_ptr,
					  struct glink_core_tx_pkt *pkt_ctx);

struct glink_transport_if {
	const char *remote_ss;
	const char *ch_name;
	tx_cmd_ch_open_fn tx_cmd_ch_open;
	tx_cmd_ch_close_fn tx_cmd_ch_close;
	tx_cmd_local_rx_done_fn tx_cmd_local_rx_done;
	tx_data_fn tx_data;
	struct glink_core_xport_ctx core_priv;
};

/* GLink-core entry points, invoked by the transport layer */
void glink_core_register_transport(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_link_up(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_link_down(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_remote_open(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_remote_close(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_ch_close_ack(struct glink_transport_if *if_ptr);
void glink_core_rx_cmd_tx_done(struct glink_transport_if *if_ptr,
			       struct glink_core_tx_pkt *tx_pkt);
void glink_core_rx_cmd_data(struct glink_transport_if *if_ptr,
			    void *ptr,
			    uint32_t size);

#endif /* __GLINK_XPORT_H */
