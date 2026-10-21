/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#include <drivers/qcom/rpm/rpm_client.h>
#include <initcall.h>
#include <stddef.h>
#include <stdint.h>
#include <trace.h>

#include "kvp.h"
#include "rpm_glink.h"
#include "rpm_protocol.h"

/* Matches the wire-packet bound rpm_client.c's predecessor used; generous
 * for a header plus a handful of KVP entries.
 */
#define RPM_TRANSPORT_MAX_PKT_SIZE	256

static TEE_Result rpm_transport_glink_open(void)
{
	enum rpm_glink_status status = rpm_glink_init();

	if (status == RPM_GLINK_OK)
		return TEE_SUCCESS;

	EMSG("RPM transport (glink): handshake failed (status=%d)", status);
	return TEE_ERROR_COMMUNICATION;
}

static TEE_Result rpm_transport_glink_tx(const void *buf, size_t len)
{
	enum rpm_glink_status status = RPM_GLINK_ERROR;

	if (len > UINT32_MAX)
		return TEE_ERROR_EXCESS_DATA;

	status = rpm_glink_tx(buf, (uint32_t)len);
	switch (status) {
	case RPM_GLINK_OK:
		return TEE_SUCCESS;
	case RPM_GLINK_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	default:
		return TEE_ERROR_COMMUNICATION;
	}
}

static TEE_Result rpm_transport_glink_poll(void)
{
	uint8_t raw[RPM_TRANSPORT_MAX_PKT_SIZE];
	uint32_t raw_len = sizeof(raw);
	enum rpm_glink_status status = RPM_GLINK_ERROR;
	struct kvp envelope = { };
	uint32_t type = 0;
	uint32_t value_len = 0;
	const uint8_t *value = NULL;

	status = rpm_glink_rx_poll(0, raw, &raw_len);
	switch (status) {
	case RPM_GLINK_OK:
		break;
	case RPM_GLINK_TIMEOUT:
		return TEE_ERROR_NO_DATA;
	case RPM_GLINK_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	default:
		return TEE_ERROR_COMMUNICATION;
	}

	kvp_init_from_buffer(&envelope, raw, raw_len);
	if (!kvp_get(&envelope, &type, &value_len, &value))
		return TEE_ERROR_NO_DATA;

	/* Not our service's envelope -- nothing for qcom_rpm_rx_callback(). */
	if (type != RPM_KVP_KEY_REQ)
		return TEE_ERROR_NO_DATA;

	return qcom_rpm_rx_callback(value, value_len);
}

static bool rpm_transport_glink_is_ready(void)
{
	return rpm_glink_is_open();
}

static const struct qcom_rpm_transport rpm_transport_glink = {
	.open = rpm_transport_glink_open,
	.tx = rpm_transport_glink_tx,
	.poll = rpm_transport_glink_poll,
	.is_ready = rpm_transport_glink_is_ready,
};

static TEE_Result rpm_transport_glink_init(void)
{
	return qcom_rpm_set_transport(&rpm_transport_glink);
}
early_init(rpm_transport_glink_init);
