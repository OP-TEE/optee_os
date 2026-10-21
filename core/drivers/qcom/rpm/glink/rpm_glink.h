/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#ifndef __RPM_GLINK_H__
#define __RPM_GLINK_H__

#include <stdbool.h>
#include <stdint.h>

enum rpm_glink_status {
	RPM_GLINK_OK = 0,
	RPM_GLINK_ERROR,
	RPM_GLINK_TIMEOUT,
	RPM_GLINK_NOT_OPEN,
};

/*
 * Map the MSG RAM FIFOs (via rpm_hal_init()) and run the version and
 * open-channel handshakes for the single "rpm" channel. Blocking,
 * bounded by a per-step timeout. Idempotent: returns RPM_GLINK_OK
 * immediately if the channel is already open. Safe to retry after a
 * failed call or after rpm_glink_deinit() -- leaves no stale state on
 * failure beyond the physical FIFO/doorbell registers themselves.
 */
enum rpm_glink_status rpm_glink_init(void);

/*
 * Reset local handshake state to closed. Does not send CLOSE_CHANNEL
 * (out of scope -- RPM_DESIGN.md Section 6); only clears this port's
 * bookkeeping so rpm_glink_init() can be retried from scratch.
 */
void rpm_glink_deinit(void);

bool rpm_glink_is_open(void);

/*
 * Frame @buf as a TX_DATA packet on the open channel and ring the
 * doorbell. Returns RPM_GLINK_NOT_OPEN if the handshake hasn't
 * completed, RPM_GLINK_ERROR if there isn't enough free space in the
 * TX fifo.
 */
enum rpm_glink_status rpm_glink_tx(const void *buf, uint32_t size);

/*
 * Poll the RX fifo for up to @timeout_us for one complete GLink
 * command. Handshake-layer commands (version/open negotiation
 * replays, e.g. a remote-initiated re-open) are handled internally
 * and never surfaced to the caller. A TX_DATA payload is copied into
 * @buf (capacity *@size on entry) and its actual length written back
 * to *@size; RPM_GLINK_ERROR if the payload doesn't fit. Returns
 * RPM_GLINK_TIMEOUT if nothing relevant arrived in time.
 */
enum rpm_glink_status rpm_glink_rx_poll(uint32_t timeout_us, void *buf,
					 uint32_t *size);

#endif /* __RPM_GLINK_H__ */
