/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __ASU_SHAREDMEM_H_
#define __ASU_SHAREDMEM_H_

#include <stdint.h>
#include <util.h>

#define ASU_MAX_BUFFERS			8U
#define ASU_CHANNEL_RESERVED_MEM	1188U
#define ASU_COMMAND_IS_PRESENT		0x1U
#define ASU_RESPONSE_IS_PRESENT		0x1U
#define ASU_RESPONSE_STATUS_INDEX	0U
#define ASU_RESPONSE_BUFF_ADDR_INDEX	1U
#define ASU_COMMAND_ID_MASK		0x0000003FU
#define ASU_UNIQUE_REQ_ID_MASK		0x00000FC0U
#define ASU_UNIQUE_REQ_ID_SHIFT		6U
#define ASU_UNIQUE_ID_MAX		SHIFT_U32(ASU_MAX_BUFFERS, 1U)
#define ASU_MODULE_ID_MASK		0x0003F000U
#define ASU_MODULE_ID_SHIFT		12U
#define ASU_COMMAND_LENGTH_SHIFT	18U
#define ASU_COMMAND_REQ_ARGS		22U
#define ASU_COMMAND_RESP_ARGS		17U
#define ASU_RTCA_BASEADDR		0xEBE40000U
#define ASU_RTCA_COMM_CHANNEL_INFO_ADDR	(ASU_RTCA_BASEADDR + 0x10U)
#define ASU_RTCA_CHANNEL_BASE_OFFSET	0x18U
#define ASU_RTCA_CHANNEL_INFO_LEN	0x8U
#define ASU_MAX_IPI_CHANNELS		8U
#define ASU_CHANNEL_MEMORY_OFFSET	0x1000U
#define ASU_CHANNEL_MEMORY_BASEADDR	(ASU_RTCA_BASEADDR + \
					 ASU_CHANNEL_MEMORY_OFFSET)

struct asu_req_buf {
	uint32_t header;
	uint32_t arg[ASU_COMMAND_REQ_ARGS];
	uint32_t reserved;
};

struct asu_resp_buf {
	uint32_t header;
	uint32_t arg[ASU_COMMAND_RESP_ARGS];
	uint32_t additionalstatus;
	uint32_t reserved;
};

struct asu_channel_queue_buf {
	uint8_t reqbufstatus;
	uint8_t respbufstatus;
	uint16_t reserved;
	struct asu_req_buf req;
	struct asu_resp_buf resp;
};

struct asu_channel_queue {
	bool cmd_is_present;
	uint32_t req_sent;
	uint32_t req_served;
	struct asu_channel_queue_buf queue_bufs[ASU_MAX_BUFFERS];
};

struct asu_channel_memory {
	uint32_t version;
	uint8_t reserved[ASU_CHANNEL_RESERVED_MEM];
	struct asu_channel_queue p0_chnl_q;
	struct asu_channel_queue p1_chnl_q;
};

#endif /* __ASU_SHAREDMEM_H_ */
