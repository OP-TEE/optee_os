/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __SBI_H
#define __SBI_H

#if defined(CFG_RISCV_SBI)

/* SBI return error codes */
#define SBI_SUCCESS			 0
#define SBI_ERR_FAILURE			-1
#define SBI_ERR_NOT_SUPPORTED		-2
#define SBI_ERR_INVALID_PARAM		-3
#define SBI_ERR_DENIED			-4
#define SBI_ERR_INVALID_ADDRESS		-5
#define SBI_ERR_ALREADY_AVAILABLE	-6
#define SBI_ERR_ALREADY_STARTED		-7
#define SBI_ERR_ALREADY_STOPPED		-8
#define SBI_ERR_ALREADY_STOPPED		-8
#define SBI_ERR_NO_SHMEM		-9
#define SBI_ERR_INVALID_STATE		-10
#define SBI_ERR_BAD_RANGE		-11
#define SBI_ERR_TIMEOUT			-12
#define SBI_ERR_IO			-13
#define SBI_ERR_DENIED_LOCKED		-14

#define SBI_LAST_ERR			SBI_ERR_DENIED_LOCKED

/* SBI Extension IDs */
#define SBI_EXT_0_1_CONSOLE_PUTCHAR	0x01
#define SBI_EXT_BASE			0x10
#define SBI_EXT_HSM			0x48534D
#define SBI_EXT_DBCN			0x4442434E
#define SBI_EXT_TEE			0x544545
#define SBI_EXT_MPXY                    0x4D505859

/* SBI function IDs for MPXY extension */
#define SBI_EXT_MPXY_GET_SHMEM_SIZE             0x0
#define SBI_EXT_MPXY_SET_SHMEM                  0x1
#define SBI_EXT_MPXY_GET_CHANNEL_IDS            0x2
#define SBI_EXT_MPXY_READ_ATTRS                 0x3
#define SBI_EXT_MPXY_WRITE_ATTRS                0x4
#define SBI_EXT_MPXY_SEND_MSG_WITH_RESP         0x5
#define SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP      0x6
#define SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS    0x7

/* Capabilities available through CHANNEL_CAPABILITY attribute */
#define SBI_MPXY_CHAN_CAP_MSI			BIT(0)
#define SBI_MPXY_CHAN_CAP_SSE			BIT(1)
#define SBI_MPXY_CHAN_CAP_EVENTS_STATE		BIT(2)
#define SBI_MPXY_CHAN_CAP_SEND_WITH_RESP	BIT(3)
#define SBI_MPXY_CHAN_CAP_SEND_WITHOUT_RESP	BIT(4)
#define SBI_MPXY_CHAN_CAP_GET_NOTIFICATIONS	BIT(5)

#ifndef __ASSEMBLER__

/* SBI function IDs for Base extension */
enum sbi_ext_base_fid {
	SBI_EXT_BASE_GET_SPEC_VERSION = 0,
	SBI_EXT_BASE_GET_IMP_ID,
	SBI_EXT_BASE_GET_IMP_VERSION,
	SBI_EXT_BASE_PROBE_EXT,
	SBI_EXT_BASE_GET_MVENDORID,
	SBI_EXT_BASE_GET_MARCHID,
	SBI_EXT_BASE_GET_MIMPID,
};

/* SBI function IDs for HSM extension */
enum sbi_ext_hsm_fid {
	SBI_EXT_HSM_HART_START = 0,
	SBI_EXT_HSM_HART_STOP,
	SBI_EXT_HSM_HART_GET_STATUS,
	SBI_EXT_HSM_HART_SUSPEND,
};

/* SBI function IDs for Debug Console extension */
enum sbi_ext_dbcn_fid {
	SBI_EXT_DBCN_CONSOLE_WRITE = 0,
	SBI_EXT_DBCN_CONSOLE_READ = 1,
	SBI_EXT_DBCN_CONSOLE_WRITE_BYTE = 2,
};

enum sbi_hsm_hart_state {
	SBI_HSM_STATE_STARTED = 0,
	SBI_HSM_STATE_STOPPED,
	SBI_HSM_STATE_START_PENDING,
	SBI_HSM_STATE_STOP_PENDING,
	SBI_HSM_STATE_SUSPENDED,
	SBI_HSM_STATE_SUSPEND_PENDING,
	SBI_HSM_STATE_RESUME_PENDING,
};

enum sbi_mpxy_attr_id {
	SBI_MPXY_ATTR_MSG_PROT_ID               = 0x00000000,
	SBI_MPXY_ATTR_MSG_PROT_VER              = 0x00000001,
	SBI_MPXY_ATTR_MSG_MAX_LEN	        = 0x00000002,
	SBI_MPXY_ATTR_MSG_SEND_TIMEOUT		= 0x00000003,
	SBI_MPXY_ATTR_MSG_COMPLETION_TIMEOUT    = 0x00000004,
	SBI_MPXY_ATTR_CHANNEL_CAPABILITY	= 0x00000005,
	SBI_MPXY_ATTR_SSE_EVENT_ID		= 0x00000006,
	SBI_MPXY_ATTR_MSI_CONTROL		= 0x00000007,
	SBI_MPXY_ATTR_MSI_ADDR_LO		= 0x00000008,
	SBI_MPXY_ATTR_MSI_ADDR_HI		= 0x00000009,
	SBI_MPXY_ATTR_MSI_DATA			= 0x0000000A,
	SBI_MPXY_ATTR_EVENTS_STATE_CONTROL	= 0x0000000B,
	SBI_MPXY_ATTR_STD_ATTR_MAX_IDX,
	SBI_MPXY_ATTR_MSGPROTO_ATTR_START	= 0x80000000,
	SBI_MPXY_ATTR_MSGPROTO_ATTR_END		= 0xffffffff
};

enum sbi_mpxy_msgproto_id {
	SBI_MPXY_MSGPROTO_RPMI_ID       = 0x00000000,
	SBI_MPXY_MSGPROTO_MAX_IDX,
	SBI_MPXY_MSGPROTO_VENDOR_START	= 0x80000000,
	SBI_MPXY_MSGPROTO_VENDOR_END	= 0xffffffff
};

/* SBI MPXY MSI related channel attributes */
struct sbi_mpxy_msi_info {
	/* MSI Address Low */
	uint32_t msi_addr_lo;
	/* MSI Address High */
	uint32_t msi_addr_hi;
	/* MSI Data */
	uint32_t msi_data;
};

/* MPXY Channel Attributes */
struct sbi_mpxy_channel_attrs {
	/* Message Protocol Identifier */
	uint32_t msg_proto_id;
	/* Message Protocol Version */
	uint32_t msg_proto_version;
	/* Maximum Message Data Length */
	uint32_t msg_max_len;
	/* Message Send Timeout */
	uint32_t msg_send_timeout;
	/* Message Completion Timeout */
	uint32_t msg_completion_timeout;
	/* Channel Capabilities Bits */
	uint32_t capability;
	/* SSE Event ID */
	uint32_t sse_event_id;
	/* MSI Control */
	uint32_t msi_control;
	/* Channel MSI info */
	struct sbi_mpxy_msi_info msi_info;
	/* Events State Control */
	uint32_t events_state_ctrl;
};

#include <compiler.h>
#include <encoding.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <types_ext.h>
#include <util.h>

int sbi_probe_extension(int extid);
void sbi_console_putchar(int ch);
int sbi_dbcn_write_byte(unsigned char ch);
int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg);
int sbi_hsm_hart_get_status(uint32_t hartid, enum sbi_hsm_hart_state *status);

#endif /*__ASSEMBLER__*/
#endif /*defined(CFG_RISCV_SBI)*/
#endif /*__SBI_H*/
