/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022, 2025 NXP
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

/* SBI MPXY channel IDs data in shared memory */
struct sbi_mpxy_channel_ids_data {
	/* Remaining number of channel ids */
	uint32_t remaining;
	/* Returned channel ids in current function call */
	uint32_t returned;
	/* Returned channel id array */
	uint32_t channel_array[];
};

/* SBI MPXY notification data in shared memory */
struct sbi_mpxy_notification_data {
	/* Remaining number of notification events */
	uint32_t remaining;
	/* Number of notification events returned */
	uint32_t returned;
	/* Number of notification events lost */
	uint32_t lost;
	/* Reserved for future use */
	uint32_t reserved;
	/* Returned channel id array */
	uint8_t events_data[];
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

/*  SBI MPXY */
int sbi_mpxy_get_shmem_size(unsigned long *shmem_size);
int sbi_mpxy_set_shmem(void);
int sbi_mpxy_get_channel_ids(uint32_t channel_count, uint32_t *channel_ids);
int sbi_mpxy_read_attributes(uint32_t channel_id, uint32_t base_attribute_id,
			     uint32_t attribute_count, void *attribute_buf);
int sbi_mpxy_write_attributes(uint32_t channel_id, uint32_t base_attribute_id,
			      uint32_t attribute_count,
			      uint32_t *attributes_buf);
int sbi_mpxy_send_message_with_response(uint32_t channel_id,
					uint32_t message_id, void *message,
					unsigned long message_len,
					void *response,
					unsigned long max_response_len,
					unsigned long *response_len);
int sbi_mpxy_send_message_without_response(uint32_t channel_id,
					   uint32_t message_id, void *message,
					   unsigned long message_len);
int sbi_mpxy_get_channel_count(uint32_t *channel_count);
int
sbi_mpxy_get_notification_events(uint32_t channel_id,
				 struct sbi_mpxy_notification_data *notif_data,
				 unsigned long *events_data_len);

#endif /*__ASSEMBLER__*/
#endif /*defined(CFG_RISCV_SBI)*/
#endif /*__SBI_H*/
