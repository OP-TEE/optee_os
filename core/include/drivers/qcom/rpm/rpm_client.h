/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_RPM_CLIENT_H__
#define __QCOM_RPM_CLIENT_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define QCOM_RPM_FOURCC(a, b, c, d) \
	((uint32_t)(a) | ((uint32_t)(b) << 8) | \
	 ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

enum qcom_rpm_set {
	QCOM_RPM_ACTIVE_SET = 0,
	QCOM_RPM_SLEEP_SET = 1,
	QCOM_RPM_NUM_SETS = 2,
};

enum qcom_rpm_resource_type {
	QCOM_RPM_TEST_REQ = QCOM_RPM_FOURCC('t', 'e', 's', 't'),
	QCOM_RPM_CLOCK_0_REQ = QCOM_RPM_FOURCC('c', 'l', 'k', '0'),
	QCOM_RPM_CLOCK_1_REQ = QCOM_RPM_FOURCC('c', 'l', 'k', '1'),
	QCOM_RPM_CLOCK_2_REQ = QCOM_RPM_FOURCC('c', 'l', 'k', '2'),
	QCOM_RPM_BUS_SLAVE_REQ = QCOM_RPM_FOURCC('b', 's', 'l', 'v'),
	QCOM_RPM_BUS_MASTER_REQ = QCOM_RPM_FOURCC('b', 'm', 'a', 's'),
	QCOM_RPM_BUS_SPDM_CLK_REQ = QCOM_RPM_FOURCC('b', 's', 'p', 'c'),
	QCOM_RPM_SMPS_A_REQ = QCOM_RPM_FOURCC('s', 'm', 'p', 'a'),
	QCOM_RPM_LDO_A_REQ = QCOM_RPM_FOURCC('l', 'd', 'o', 'a'),
	QCOM_RPM_NCP_A_REQ = QCOM_RPM_FOURCC('n', 'c', 'p', 'a'),
	QCOM_RPM_VS_A_REQ = QCOM_RPM_FOURCC('v', 's', 'a', '\0'),
	QCOM_RPM_CLK_BUFFER_A_REQ = QCOM_RPM_FOURCC('c', 'l', 'k', 'a'),
	QCOM_RPM_SMPS_B_REQ = QCOM_RPM_FOURCC('s', 'm', 'p', 'b'),
	QCOM_RPM_LDO_B_REQ = QCOM_RPM_FOURCC('l', 'd', 'o', 'b'),
	QCOM_RPM_NCP_B_REQ = QCOM_RPM_FOURCC('n', 'c', 'p', 'b'),
	QCOM_RPM_VS_B_REQ = QCOM_RPM_FOURCC('v', 's', 'b', '\0'),
	QCOM_RPM_CLK_BUFFER_B_REQ = QCOM_RPM_FOURCC('c', 'l', 'k', 'b'),
	QCOM_RPM_OCMEM_POWER_REQ = QCOM_RPM_FOURCC('o', 'c', 'm', 'p'),
};

struct qcom_rpm_kvp {
	uint32_t key;
	const void *data;
	size_t len;
};

struct qcom_rpm_transport {
	TEE_Result (*open)(void);
	TEE_Result (*tx)(const void *buf, size_t len);
	TEE_Result (*poll)(void);
	bool (*is_ready)(void);
};

TEE_Result qcom_rpm_set_transport(const struct qcom_rpm_transport *transport);
TEE_Result qcom_rpm_init(void);
bool qcom_rpm_is_up(void);

TEE_Result qcom_rpm_post_request(enum qcom_rpm_set set, uint32_t resource,
				 uint32_t id, const struct qcom_rpm_kvp *kvps,
				 size_t num_kvps, uint32_t *msg_id);
TEE_Result qcom_rpm_force_sync(enum qcom_rpm_set set, uint32_t *last_msg_id);
TEE_Result qcom_rpm_send_kvp_buffer(enum qcom_rpm_set set, uint32_t resource,
				    uint32_t id, const void *kvp_buf,
				    size_t kvp_len, uint32_t *msg_id);
TEE_Result qcom_rpm_barrier(uint32_t msg_id, uint32_t timeout_us);
TEE_Result qcom_rpm_rx_callback(const void *buf, size_t len);

/*
 * Compatibility helper for TZ-style users that already compose an RPM KVP
 * buffer. It sends synchronously best-effort and drops the returned msg_id.
 */
void ubsp_rpm_send(uint32_t resource_type, uint32_t id, uint32_t set,
		   uint8_t *kvps, uint32_t len);

#endif /* __QCOM_RPM_CLIENT_H__ */
