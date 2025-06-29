/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __SBI_MPXY_H
#define __SBI_MPXY_H

#if defined(CFG_RISCV_SBI_MPXY)

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

#include <compiler.h>
#include <encoding.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <types_ext.h>
#include <util.h>

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

/*
 * struct sbi_mpxy_msi_info - MSI-related attributes for an MPXY channel
 * @msi_addr_lo: Lower 32 bits of the MSI address
 * @msi_addr_hi: Upper 32 bits of the MSI address
 * @msi_data:    MSI data payload to be written
 *
 * Describes the MSI configuration used for sending interrupts from
 * the SBI implementation to the supervisor software via MPXY channels.
 */
struct sbi_mpxy_msi_info {
	uint32_t msi_addr_lo;
	uint32_t msi_addr_hi;
	uint32_t msi_data;
};

/*
 * struct sbi_mpxy_channel_attrs - Attributes describing an MPXY channel
 * @msg_proto_id:         Protocol identifier used on this channel (e.g., RPMI)
 * @msg_proto_version:    Version of the protocol supported on this channel
 * @msg_max_len:          Maximum length (in bytes) of the message payload
 * @msg_send_timeout:     Timeout (in microseconds) for sending a message
 * @msg_completion_timeout: Timeout (in microseconds) to wait for a response
 * @capability:           Bitfield indicating supported channel capabilities
 * @sse_event_id:         SSE event ID used for signaling events (if supported)
 * @msi_control:          Bitmask for controlling MSI behavior (e.g., enable)
 * @msi_info:             MSI configuration (address/data) for the channel
 * @events_state_ctrl:    Control register for event state handling
 *
 * These attributes are retrieved from the SBI implementation via
 * SBI_MPXY_ATTR_* queries and describe the static properties of
 * an MPXY channel.
 */
struct sbi_mpxy_channel_attrs {
	uint32_t msg_proto_id;
	uint32_t msg_proto_version;
	uint32_t msg_max_len;
	uint32_t msg_send_timeout;
	uint32_t msg_completion_timeout;
	uint32_t capability;
	uint32_t sse_event_id;
	uint32_t msi_control;
	struct sbi_mpxy_msi_info msi_info;
	uint32_t events_state_ctrl;
};

/*
 * struct sbi_mpxy_channel_ids_data - MPXY channel ID list structure
 * @remaining:     Number of channel IDs remaining after this call
 * @returned:      Number of channel IDs returned in this call
 * @channel_array: Array of channel IDs returned by the SBI call
 *
 * This structure is used for retrieving channel IDs from the SBI
 * implementation via shared memory. It supports partial retrieval
 * when the number of available IDs exceeds the buffer capacity.
 */
struct sbi_mpxy_channel_ids_data {
	uint32_t remaining;
	uint32_t returned;
	uint32_t channel_array[];
};

/*
 * struct sbi_mpxy_notification_data - MPXY notification event structure
 * @remaining:    Number of notification events remaining after this call
 * @returned:     Number of notification events returned in this call
 * @lost:         Number of notification events lost due to buffer overflow
 * @reserved:     Reserved for future use (must be zero)
 * @events_data:  Raw event data blob, format defined by the message protocol
 *
 * This structure is populated in shared memory by the SBI implementation
 * to deliver asynchronous notification events to the supervisor software.
 */
struct sbi_mpxy_notification_data {
	uint32_t remaining;
	uint32_t returned;
	uint32_t lost;
	uint32_t reserved;
	uint8_t events_data[];
};

/* SBI MPXY */
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
#endif /*defined(CFG_RISCV_SBI_MPXY)*/
#endif /*__SBI_MPXY_H*/
