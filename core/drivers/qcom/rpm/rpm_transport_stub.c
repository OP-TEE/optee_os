// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/rpm/rpm_client.h>
#include <initcall.h>
#include <trace.h>

static TEE_Result rpm_stub_open(void)
{
	IMSG("QCOM RPM transport is stubbed; GLINK/IPCC backend not available");
	return TEE_SUCCESS;
}

static TEE_Result rpm_stub_tx(const void *buf __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result rpm_stub_poll(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static bool rpm_stub_is_ready(void)
{
	return false;
}

static const struct qcom_rpm_transport rpm_stub_transport = {
	.open = rpm_stub_open,
	.tx = rpm_stub_tx,
	.poll = rpm_stub_poll,
	.is_ready = rpm_stub_is_ready,
};

static TEE_Result rpm_stub_transport_init(void)
{
	return qcom_rpm_set_transport(&rpm_stub_transport);
}
early_init(rpm_stub_transport_init);
