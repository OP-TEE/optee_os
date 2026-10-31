// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/rpm/rpm_client.h>
#include <util.h>

#include "qfprom_rpm.h"

/* Shikra's legacy RPM QFPROM rail is ldoa13. */
#define QFPROM_RPM_VREG_ID		13
#define QFPROM_RPM_VOLTAGE_UV		1800000
#define QFPROM_RPM_CURRENT_MA		100
#define QFPROM_RPM_HEADROOM_UV		25
#define QFPROM_RPM_MODE_IPEAK		0
#define QFPROM_RPM_MODE_NPM		1
#define QFPROM_RPM_BYPASS_ALLOWED	0
#define QFPROM_RPM_BYPASS_DISALLOWED	1

#define QFPROM_RPM_KEY_ENABLE		0x6e657773 /* swen */
#define QFPROM_RPM_KEY_MODE		0x646d736c /* lsmd */
#define QFPROM_RPM_KEY_PIN_ENABLE	0x6e656370 /* pcen */
#define QFPROM_RPM_KEY_PIN_MODE		0x646d6370 /* pcmd */
#define QFPROM_RPM_KEY_VOLTAGE		0x7675 /* uv */
#define QFPROM_RPM_KEY_CURRENT		0x616d /* ma */
#define QFPROM_RPM_KEY_HEADROOM		0x7268 /* hr */
#define QFPROM_RPM_KEY_BYPASS		0x61707962 /* bypa */
#define QFPROM_RPM_KEY_CORNER		0x6e726f63 /* corn */

static TEE_Result qfprom_rpm_vote(bool enable)
{
	const uint32_t sw_enable = enable ? 1 : 0;
	const uint32_t mode = enable ? QFPROM_RPM_MODE_NPM :
				      QFPROM_RPM_MODE_IPEAK;
	const uint32_t pin_enable = 0;
	const uint32_t pin_mode = 0;
	const uint32_t voltage = enable ? QFPROM_RPM_VOLTAGE_UV : 0;
	const uint32_t current = enable ? QFPROM_RPM_CURRENT_MA : 0;
	const uint32_t headroom = enable ? QFPROM_RPM_HEADROOM_UV : 0;
	const uint32_t bypass = enable ? QFPROM_RPM_BYPASS_DISALLOWED :
					 QFPROM_RPM_BYPASS_ALLOWED;
	const uint32_t corner = enable ? QFPROM_RPM_VOLTAGE_UV : 0;
	const struct qcom_rpm_kvp kvps[] = {
		{ QFPROM_RPM_KEY_ENABLE, &sw_enable, sizeof(sw_enable) },
		{ QFPROM_RPM_KEY_MODE, &mode, sizeof(mode) },
		{ QFPROM_RPM_KEY_PIN_ENABLE, &pin_enable, sizeof(pin_enable) },
		{ QFPROM_RPM_KEY_PIN_MODE, &pin_mode, sizeof(pin_mode) },
		{ QFPROM_RPM_KEY_VOLTAGE, &voltage, sizeof(voltage) },
		{ QFPROM_RPM_KEY_CURRENT, &current, sizeof(current) },
		{ QFPROM_RPM_KEY_HEADROOM, &headroom, sizeof(headroom) },
		{ QFPROM_RPM_KEY_BYPASS, &bypass, sizeof(bypass) },
		{ QFPROM_RPM_KEY_CORNER, &corner, sizeof(corner) },
	};
	uint32_t msg_id = 0;
	TEE_Result ret = TEE_SUCCESS;

	ret = qcom_rpm_post_request(QCOM_RPM_ACTIVE_SET,
				    QCOM_RPM_LDO_A_REQ, QFPROM_RPM_VREG_ID,
				    kvps, ARRAY_SIZE(kvps), &msg_id);
	if (ret)
		return ret;

	return qcom_rpm_barrier(msg_id, 10000);
}

TEE_Result qfprom_rpm_enable(void)
{
	return qfprom_rpm_vote(true);
}

TEE_Result qfprom_rpm_disable(void)
{
	return qfprom_rpm_vote(false);
}
