// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#include <inttypes.h>
#include <kernel/delay.h>
#include <stdbool.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#include "rpm_glink.h"
#include "rpm_hal.h"
#include "rpm_protocol.h"

#define RPM_GLINK_STEP_TIMEOUT_US	100000

#define RPM_GLINK_LOCAL_CH_NAME		"rpm_requests"

enum rpm_glink_state {
	RPM_GLINK_ST_CLOSED = 0,
	RPM_GLINK_ST_VERSION_SENT,
	RPM_GLINK_ST_VERSION_ACKED,
	RPM_GLINK_ST_CHANNEL_SENT,
	RPM_GLINK_ST_OPEN,
};

static struct rpm_hal_fifo tx_fifo;
static struct rpm_hal_fifo rx_fifo;
static bool hal_ready;
static enum rpm_glink_state state = RPM_GLINK_ST_CLOSED;
static bool local_open_acked;
static bool remote_open_acked;
static uint32_t rcid; /* RPM's channel id, learned from its OPEN_CHANNEL */

static enum rpm_glink_status rpm_glink_send(const void *cmd, uint32_t cmd_size,
					     const void *data,
					     uint32_t data_size)
{
	uint32_t total_size = cmd_size + data_size;
	uint32_t reserve_size = ROUNDUP(total_size, 8);
	uint32_t orig_write_ind = rpm_hal_fifo_write_ind(&tx_fifo);
	uint32_t write_ind = orig_write_ind;
	uint32_t read_ind = rpm_hal_fifo_read_ind(&tx_fifo);
	uint32_t avail;
	uint32_t raw[8] = { 0 };
	uint32_t dump_words;

	if (write_ind >= tx_fifo.size || read_ind >= tx_fifo.size)
		return RPM_GLINK_ERROR;

	avail = write_ind < read_ind ? read_ind - write_ind :
		tx_fifo.size - write_ind + read_ind;


	if (reserve_size + sizeof(uint64_t) > avail) {
		EMSG("RPM glink: TX fifo full, dropping frame");
		return RPM_GLINK_ERROR;
	}

	write_ind = rpm_hal_fifo_write(&tx_fifo, write_ind, cmd, cmd_size);
	if (data && data_size)
		write_ind = rpm_hal_fifo_write(&tx_fifo, write_ind, data,
						data_size);

	write_ind += reserve_size - ROUNDUP(total_size, 4);
	if (write_ind >= tx_fifo.size)
		write_ind -= tx_fifo.size;

	rpm_hal_fifo_set_write_ind(&tx_fifo, write_ind);

	dump_words = MIN(reserve_size / sizeof(uint32_t),
			  (uint32_t)ARRAY_SIZE(raw));
	rpm_hal_fifo_read(&tx_fifo, orig_write_ind, raw,
			   dump_words * sizeof(uint32_t));

	rpm_hal_ring_doorbell();


	return RPM_GLINK_OK;
}

static enum rpm_glink_status rpm_glink_send_version(uint32_t cmd_id,
						      uint32_t version,
						      uint32_t features)
{
	uint32_t cmd[2] = {
		rpm_glink_make_version_cmd(cmd_id, version),
		features,
	};

	return rpm_glink_send(cmd, sizeof(cmd), NULL, 0);
}

static enum rpm_glink_status rpm_glink_send_open_channel(void)
{
	uint32_t name_len = sizeof(RPM_GLINK_LOCAL_CH_NAME); /* incl. NUL */
	uint32_t cmd[2] = {
		rpm_glink_make_cmd(RPM_GLINK_CMD_OPEN_CHANNEL,
				    RPM_GLINK_CHANNEL_ID),
		name_len,
	};


	return rpm_glink_send(cmd, sizeof(cmd), RPM_GLINK_LOCAL_CH_NAME,
			       name_len);
}

/* Ack a remote-initiated OPEN_CHANNEL, echoing RPM's own channel id. */
static enum rpm_glink_status rpm_glink_send_open_channel_ack(uint32_t ack_rcid)
{
	uint32_t cmd = rpm_glink_make_cmd(RPM_GLINK_CMD_OPEN_CHANNEL_ACK,
					    ack_rcid);


	return rpm_glink_send(&cmd, sizeof(cmd), NULL, 0);
}

/* Both halves of the channel-open handshake complete -- see the comment
 * on local_open_acked/remote_open_acked above.
 */
static void rpm_glink_update_open_state(void)
{
	if (local_open_acked && remote_open_acked &&
	    state == RPM_GLINK_ST_CHANNEL_SENT) {
		state = RPM_GLINK_ST_OPEN;
	}
}

/* Read one word off the rx fifo at @cursor, returning the new cursor. */
static uint32_t rpm_glink_read_word(uint32_t cursor, uint32_t *word)
{
	return rpm_hal_fifo_read(&rx_fifo, cursor, word, sizeof(*word));
}

enum rpm_glink_rx_result {
	RPM_GLINK_RX_NONE,	/* nothing pending */
	RPM_GLINK_RX_HANDLED,	/* a command was consumed, nothing for caller */
	RPM_GLINK_RX_DATA,	/* a TX_DATA payload was copied out */
	RPM_GLINK_RX_ERROR,	/* malformed frame -- caller must reset */
};

static enum rpm_glink_rx_result
rpm_glink_rx_dispatch_one(void *data_buf, uint32_t data_cap,
			   uint32_t *data_len)
{
	uint32_t write_ind = rpm_hal_fifo_write_ind(&rx_fifo);
	uint32_t read_ind = rpm_hal_fifo_read_ind(&rx_fifo);
	uint32_t cursor;
	uint32_t cmd;
	uint32_t cmd_id;
	bool got_data = false;

	if (write_ind >= rx_fifo.size || read_ind >= rx_fifo.size)
		return RPM_GLINK_RX_ERROR;

	if (write_ind == read_ind)
		return RPM_GLINK_RX_NONE;

	cursor = rpm_glink_read_word(read_ind, &cmd);
	cmd_id = rpm_glink_cmd_id(cmd);


	switch (cmd_id) {
	case RPM_GLINK_CMD_VERSION_REQ: {
		uint32_t remote_version = rpm_glink_version(cmd);
		uint32_t remote_features;

		cursor = rpm_glink_read_word(cursor, &remote_features);

		rpm_glink_send_version(RPM_GLINK_CMD_VERSION_ACK,
					RPM_GLINK_LOCAL_VERSION,
					RPM_GLINK_LOCAL_FEATURES);

		if (remote_version == RPM_GLINK_LOCAL_VERSION &&
		    remote_features == RPM_GLINK_LOCAL_FEATURES &&
		    state == RPM_GLINK_ST_VERSION_SENT)
			state = RPM_GLINK_ST_VERSION_ACKED;
		break;
	}
	case RPM_GLINK_CMD_VERSION_ACK: {
		uint32_t remote_version = rpm_glink_version(cmd);
		uint32_t remote_features;

		cursor = rpm_glink_read_word(cursor, &remote_features);

		if (remote_version == RPM_GLINK_LOCAL_VERSION &&
		    remote_features == RPM_GLINK_LOCAL_FEATURES) {
			if (state == RPM_GLINK_ST_VERSION_SENT)
				state = RPM_GLINK_ST_VERSION_ACKED;
		}
		break;
	}
	case RPM_GLINK_CMD_OPEN_CHANNEL_ACK: {
		uint32_t ack_lcid = rpm_glink_channel_id(cmd);

		if (ack_lcid == RPM_GLINK_CHANNEL_ID) {
			local_open_acked = true;
			rpm_glink_update_open_state();
		}
		break;
	}
	case RPM_GLINK_CMD_OPEN_CHANNEL: {
		uint32_t name_len;
		uint32_t remote_rcid = rpm_glink_channel_id(cmd);

		cursor = rpm_glink_read_word(cursor, &name_len);
		name_len = ROUNDUP(name_len, 8);
		if (name_len == 0 || name_len >= rx_fifo.size)
			return RPM_GLINK_RX_ERROR;
		cursor = (cursor + name_len) % rx_fifo.size;
		rcid = remote_rcid;
		if (rpm_glink_send_open_channel_ack(remote_rcid) ==
		    RPM_GLINK_OK) {
			remote_open_acked = true;
			rpm_glink_update_open_state();
		}
		break;
	}
	case RPM_GLINK_CMD_CLOSE_CHANNEL:
	case RPM_GLINK_CMD_CLOSE_CHANNEL_ACK:
	case RPM_GLINK_CMD_TX_SIGNALS:
		/* unused; fixed-size frames, consumed by the roundup below */
		break;
	case RPM_GLINK_CMD_TX_DATA: {
		uint32_t reserved = 0;
		uint32_t len;

		cursor = rpm_glink_read_word(cursor, &reserved);
		cursor = rpm_glink_read_word(cursor, &len);
		cursor = rpm_glink_read_word(cursor, &reserved);

		if (len >= rx_fifo.size)
			return RPM_GLINK_RX_ERROR;

		if (data_buf && data_len) {
			if (len > data_cap)
				return RPM_GLINK_RX_ERROR;
			cursor = rpm_hal_fifo_read(&rx_fifo, cursor, data_buf,
						    len);
			*data_len = len;
			got_data = true;
		} else {
			cursor = (cursor + len) % rx_fifo.size;
		}
		break;
	}
	default:
		EMSG("RPM glink: unknown cmd_id=0x%"PRIx32", dropping link",
		     cmd_id);
		return RPM_GLINK_RX_ERROR;
	}

	read_ind = ROUNDUP(cursor, 8);
	if (read_ind >= rx_fifo.size)
		read_ind -= rx_fifo.size;
	rpm_hal_fifo_set_read_ind(&rx_fifo, read_ind);

	return got_data ? RPM_GLINK_RX_DATA : RPM_GLINK_RX_HANDLED;
}

/* Run @cond-while-polling, bounded by RPM_GLINK_STEP_TIMEOUT_US. */
static enum rpm_glink_status rpm_glink_wait_state(enum rpm_glink_state want)
{
	uint64_t timer = timeout_init_us(RPM_GLINK_STEP_TIMEOUT_US);

	while (state != want && !timeout_elapsed(timer)) {
		enum rpm_glink_rx_result res =
			rpm_glink_rx_dispatch_one(NULL, 0, NULL);

		if (res == RPM_GLINK_RX_ERROR)
			return RPM_GLINK_ERROR;
		if (res == RPM_GLINK_RX_NONE)
			udelay(1);
	}

	if (state != want)
		EMSG("RPM glink: wait_state(%d) timed out in state=%d, rx write_ind=%"PRIu32" read_ind=%"PRIu32" doorbell_pending=%#"PRIx32,
		     want, state, rpm_hal_fifo_write_ind(&rx_fifo),
		     rpm_hal_fifo_read_ind(&rx_fifo),
		     rpm_hal_doorbell_poll());

	return state == want ? RPM_GLINK_OK : RPM_GLINK_TIMEOUT;
}

enum rpm_glink_status rpm_glink_init(void)
{
	enum rpm_glink_status status;

	if (state == RPM_GLINK_ST_OPEN)
		return RPM_GLINK_OK;

	if (!hal_ready) {
		enum rpm_hal_status hal_status;

		hal_status = rpm_hal_init(RPM_FIFO_ID_TZ2R, RPM_FIFO_ID_R2TZ,
					   &tx_fifo, &rx_fifo);
		if (hal_status != RPM_HAL_OK) {
			EMSG("RPM glink: HAL init failed (status=%d)",
			     hal_status);
			return RPM_GLINK_ERROR;
		}
		hal_ready = true;
	}

	if (rpm_glink_send_version(RPM_GLINK_CMD_VERSION_REQ,
				    RPM_GLINK_LOCAL_VERSION,
				    RPM_GLINK_LOCAL_FEATURES) != RPM_GLINK_OK) {
		EMSG("RPM glink: failed to send VERSION_REQ");
		return RPM_GLINK_ERROR;
	}
	state = RPM_GLINK_ST_VERSION_SENT;

	status = rpm_glink_wait_state(RPM_GLINK_ST_VERSION_ACKED);
	if (status != RPM_GLINK_OK) {
		EMSG("RPM glink: version handshake failed (status=%d)",
		     status);
		rpm_glink_deinit();
		return status;
	}

	if (rpm_glink_send_open_channel() != RPM_GLINK_OK) {
		EMSG("RPM glink: failed to send OPEN_CHANNEL");
		rpm_glink_deinit();
		return RPM_GLINK_ERROR;
	}
	state = RPM_GLINK_ST_CHANNEL_SENT;

	status = rpm_glink_wait_state(RPM_GLINK_ST_OPEN);
	if (status != RPM_GLINK_OK) {
		EMSG("RPM glink: channel-open handshake failed (status=%d)",
		     status);
		rpm_glink_deinit();
		return status;
	}


	return RPM_GLINK_OK;
}

void rpm_glink_deinit(void)
{
	state = RPM_GLINK_ST_CLOSED;
}

bool rpm_glink_is_open(void)
{
	return state == RPM_GLINK_ST_OPEN;
}

enum rpm_glink_status rpm_glink_tx(const void *buf, uint32_t size)
{
	uint32_t cmd[4];

	if (state != RPM_GLINK_ST_OPEN)
		return RPM_GLINK_NOT_OPEN;

	cmd[0] = rpm_glink_make_cmd(RPM_GLINK_CMD_TX_DATA,
				     RPM_GLINK_CHANNEL_ID);
	cmd[1] = 0;
	cmd[2] = size;
	cmd[3] = 0;

	return rpm_glink_send(cmd, sizeof(cmd), buf, size);
}

enum rpm_glink_status rpm_glink_rx_poll(uint32_t timeout_us, void *buf,
					 uint32_t *size)
{
	uint64_t timer;

	if (!buf || !size)
		return RPM_GLINK_ERROR;

	if (state != RPM_GLINK_ST_OPEN)
		return RPM_GLINK_NOT_OPEN;

	timer = timeout_init_us(timeout_us);
	do {
		enum rpm_glink_rx_result res =
			rpm_glink_rx_dispatch_one(buf, *size, size);

		if (res == RPM_GLINK_RX_DATA)
			return RPM_GLINK_OK;

		if (res == RPM_GLINK_RX_ERROR) {
			EMSG("RPM glink: malformed frame during rx_poll");
			rpm_glink_deinit();
			return RPM_GLINK_ERROR;
		}

		if (res == RPM_GLINK_RX_NONE)
			udelay(1);
	} while (!timeout_elapsed(timer));

	return RPM_GLINK_TIMEOUT;
}
