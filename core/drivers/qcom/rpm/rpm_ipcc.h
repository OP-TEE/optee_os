/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */


#ifndef __RPM_IPCC_H__
#define __RPM_IPCC_H__

#include <stdint.h>
#include <types_ext.h>
#include <util.h>

#define RPM_IPCC_SEND_OFFS			0xc
#define RPM_IPCC_RECV_ID_OFFS			0x10
#define RPM_IPCC_RECV_SIGNAL_ENABLE_OFFS	0x14
#define RPM_IPCC_RECV_SIGNAL_DISABLE_OFFS	0x18
#define RPM_IPCC_RECV_SIGNAL_CLEAR_OFFS		0x1c

#define RPM_IPCC_PROTOCOL_STRIDE		0x40000
#define RPM_IPCC_CLIENT_STRIDE			0x1000

#define RPM_IPCC_CLIENT_ID_SHIFT		0x10

/* IPC_RECV_ID value when no signal is pending. */
#define RPM_IPCC_NO_DATA			UINT32_C(0xFFFFFFFF)
#define RPM_IPCC_SID_MASK			0xFFFF

static inline uint32_t rpm_ipcc_reg(vaddr_t base, uint32_t protocol,
				     uint32_t client, uint32_t reg_offs)
{
	return base + reg_offs +
	       RPM_IPCC_PROTOCOL_STRIDE * protocol +
	       RPM_IPCC_CLIENT_STRIDE * client;
}

/*
 * The value to write to IPC_SEND() to trigger @signal_idx on
 * @dest_client.
 */
static inline uint32_t rpm_ipcc_sigen(uint32_t dest_client,
				       uint32_t signal_idx)
{
	return SHIFT_U32(dest_client, RPM_IPCC_CLIENT_ID_SHIFT) | signal_idx;
}

/*
 * Decode a raw IPC_RECV_ID value into sender client id / signal id.
 * same {client_id, signal_idx} packing as the trigger write above.
 */
static inline uint32_t rpm_ipcc_recv_cid(uint32_t raw)
{
	return (raw >> RPM_IPCC_CLIENT_ID_SHIFT) & RPM_IPCC_SID_MASK;
}

static inline uint32_t rpm_ipcc_recv_sid(uint32_t raw)
{
	return raw & RPM_IPCC_SID_MASK;
}

#endif /* __RPM_IPCC_H__ */
