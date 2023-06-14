/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016-2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Lokesh Vutla <lokeshvutla@ti.com>
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#ifndef TI_SCI_PROTOCOL_H
#define TI_SCI_PROTOCOL_H

#include <compiler.h>
#include <stdint.h>
#include <util.h>

/* Generic Messages */
#define TI_SCI_MSG_VERSION               0x0002

/* Device requests */
#define TI_SCI_MSG_SET_DEVICE_STATE      0x0200

/* Security Management Messages */
#define TI_SCI_MSG_FWL_SET               0x9000
#define TI_SCI_MSG_FWL_GET               0x9001
#define TI_SCI_MSG_FWL_CHANGE_OWNER      0x9002
#define TI_SCI_MSG_SA2UL_GET_DKEK        0x9029
#define TI_SCI_MSG_READ_OTP_MMR          0x9022
#define TI_SCI_MSG_WRITE_OTP_ROW         0x9023
#define TI_SCI_MSG_LOCK_OTP_ROW          0x9024

/* OTP Revision Read/Write Message Description */
#define TI_SCI_MSG_WRITE_SWREV           0x9032
#define TI_SCI_MSG_READ_SWREV            0x9033
#define TI_SCI_MSG_READ_KEYCNT_KEYREV    0x9034
#define TI_SCI_MSG_WRITE_KEYREV          0x9035

/**
 * struct ti_sci_secure_msg_hdr - Secure Message Header for All messages
 *				 and responses
 *
 * @checksum:	Integrity check for HS devices
 * @reserved:	Reserved for future uses
 */
struct ti_sci_secure_msg_hdr {
	uint16_t checksum;
	uint16_t reserved;
} __packed;

/**
 * struct ti_sci_msg_hdr - Generic Message Header for All messages and responses
 * @type:	Type of messages: One of TI_SCI_MSG* values
 * @host:	Host of the message
 * @seq:	Message identifier indicating a transfer sequence
 * @flags:	Flag for the message
 */
struct ti_sci_msg_hdr {
	struct ti_sci_secure_msg_hdr sec_hdr;
	uint16_t type;
	uint8_t host;
	uint8_t seq;
#define TI_SCI_MSG_FLAG(val)			BIT(val)
#define TI_SCI_FLAG_REQ_GENERIC_NORESPONSE	0x0
#define TI_SCI_FLAG_REQ_ACK_ON_RECEIVED		TI_SCI_MSG_FLAG(0)
#define TI_SCI_FLAG_REQ_ACK_ON_PROCESSED	TI_SCI_MSG_FLAG(1)
#define TI_SCI_FLAG_RESP_GENERIC_NACK		0x0
#define TI_SCI_FLAG_RESP_GENERIC_ACK		TI_SCI_MSG_FLAG(1)
	/* Additional Flags */
	uint32_t flags;
} __packed;

/**
 * struct ti_sci_msg_version_req - Request for firmware version information
 * @hdr:	Generic header
 *
 * Request for TI_SCI_MSG_VERSION
 */
struct ti_sci_msg_req_version {
	struct ti_sci_msg_hdr hdr;
} __packed;

/**
 * struct ti_sci_msg_resp_version - Response for firmware version information
 * @hdr:		Generic header
 * @firmware_description: String describing the firmware
 * @firmware_revision:	Firmware revision
 * @abi_major:		Major version of the ABI that firmware supports
 * @abi_minor:		Minor version of the ABI that firmware supports
 * @sub_version:	Sub-version number of the firmware
 * @patch_version:	Patch-version number of the firmware.
 *
 * In general, ABI version changes follow the rule that minor version increments
 * are backward compatible. Major revision changes in ABI may not be
 * backward compatible.
 *
 * Response to request TI_SCI_MSG_VERSION
 */
struct ti_sci_msg_resp_version {
	struct ti_sci_msg_hdr hdr;
#define FIRMWARE_DESCRIPTION_LENGTH 32
	char firmware_description[FIRMWARE_DESCRIPTION_LENGTH];
	uint16_t firmware_revision;
	uint8_t abi_major;
	uint8_t abi_minor;
	uint8_t sub_version;
	uint8_t patch_version;
} __packed;

/**
 * struct ti_sci_msg_req_set_device_state - Set the desired state of the device
 * @hdr:	Generic header
 * @id:		Indicates which device to modify
 * @reserved:	Reserved space in message, must be 0 for backward compatibility
 * @state:	The desired state of the device.
 *
 * Certain flags can also be set to alter the device state:
 * + MSG_FLAG_DEVICE_WAKE_ENABLED - Configure the device to be a wake source.
 * The meaning of this flag will vary slightly from device to device and from
 * SoC to SoC but it generally allows the device to wake the SoC out of deep
 * suspend states.
 * + MSG_FLAG_DEVICE_RESET_ISO - Enable reset isolation for this device.
 * + MSG_FLAG_DEVICE_EXCLUSIVE - Claim this device exclusively. When passed
 * with STATE_RETENTION or STATE_ON, it will claim the device exclusively.
 * If another host already has this device set to STATE_RETENTION or STATE_ON,
 * the message will fail. Once successful, other hosts attempting to set
 * STATE_RETENTION or STATE_ON will fail.
 *
 * Request type is TI_SCI_MSG_SET_DEVICE_STATE, responded with a generic
 * ACK/NACK message.
 */
struct ti_sci_msg_req_set_device_state {
	/* Additional hdr->flags options */
#define MSG_FLAG_DEVICE_WAKE_ENABLED	TI_SCI_MSG_FLAG(8)
#define MSG_FLAG_DEVICE_RESET_ISO	TI_SCI_MSG_FLAG(9)
#define MSG_FLAG_DEVICE_EXCLUSIVE	TI_SCI_MSG_FLAG(10)
	struct ti_sci_msg_hdr hdr;
	uint32_t id;
	uint32_t reserved;

#define MSG_DEVICE_SW_STATE_AUTO_OFF	0
#define MSG_DEVICE_SW_STATE_RETENTION	1
#define MSG_DEVICE_SW_STATE_ON		2
	uint8_t state;
} __packed;

/**
 * struct ti_sci_msg_resp_set_device_state - Response for set device state
 * @hdr:	Generic header
 *
 * Response to request TI_SCI_MSG_SET_DEVICE_STATE
 */
struct ti_sci_msg_resp_set_device_state {
	struct ti_sci_msg_hdr hdr;
} __packed;

#define FWL_MAX_PRIVID_SLOTS 3U

/**
 * struct ti_sci_msg_req_fwl_set_firewall_region - Set firewall permissions
 * @hdr:		Generic Header
 * @fwl_id:		Firewall ID
 * @region:		Region or channel number to set config info.
 *			This field is unused in case of a simple firewall and
 *			must be initialized to zero.  In case of a region based
 *			firewall, this field indicates the region (index
 *			starting from 0). In case of a channel based firewall,
 *			this field indicates the channel (index starting
 *			from 0).
 * @n_permission_regs:	Number of permission registers to set
 * @control:		Contents of the firewall CONTROL register to set
 * @permissions:	Contents of the firewall PERMISSION register to set
 * @start_address:	Contents of the firewall START_ADDRESS register to set
 * @end_address:	Contents of the firewall END_ADDRESS register to set
 */
struct ti_sci_msg_req_fwl_set_firewall_region {
	struct ti_sci_msg_hdr hdr;
	uint16_t fwl_id;
	uint16_t region;
	uint32_t n_permission_regs;
	uint32_t control;
	uint32_t permissions[FWL_MAX_PRIVID_SLOTS];
	uint64_t start_address;
	uint64_t end_address;
} __packed;

struct ti_sci_msg_resp_fwl_set_firewall_region {
	struct ti_sci_msg_hdr hdr;
} __packed;

/**
 * struct ti_sci_msg_req_fwl_get_firewall_region - Retrieve firewall permissions
 * @hdr:		Generic Header
 * @fwl_id:		Firewall ID in question
 * @region:		Region or channel number to set config info.
 *			This field is unused in case of a simple firewall and
 *			must be initialized to zero.  In case of a region based
 *			firewall, this field indicates the region (index
 *			starting from 0). In case of a channel based firewall,
 *			this field indicates the channel (index starting
 *			from 0).
 * @n_permission_regs:	Number of permission registers to retrieve
 */
struct ti_sci_msg_req_fwl_get_firewall_region {
	struct ti_sci_msg_hdr hdr;
	uint16_t fwl_id;
	uint16_t region;
	uint32_t n_permission_regs;
} __packed;

/**
 * struct ti_sci_msg_resp_fwl_get_firewall_region - Response for retrieving the
 *						    firewall permissions
 *
 * @hdr:		Generic Header
 *
 * @fwl_id:		Firewall ID in question
 * @region:		Region or channel number to set config info.
 *			This field is unused in case of a simple firewall and
 *			must be initialized to zero.  In case of a region based
 *			firewall, this field indicates the region (index
 *			starting from 0). In case of a channel based firewall,
 *			this field indicates the channel (index starting
 *			from 0).
 * @n_permission_regs:	Number of permission registers retrieved
 * @control:		Contents of the firewall CONTROL register
 * @permissions:	Contents of the firewall PERMISSION registers
 * @start_address:	Contents of the firewall START_ADDRESS register
 * @end_address:	Contents of the firewall END_ADDRESS register
 */
struct ti_sci_msg_resp_fwl_get_firewall_region {
	struct ti_sci_msg_hdr hdr;
	uint16_t fwl_id;
	uint16_t region;
	uint32_t n_permission_regs;
	uint32_t control;
	uint32_t permissions[FWL_MAX_PRIVID_SLOTS];
	uint64_t start_address;
	uint64_t end_address;
} __packed;

/**
 * struct ti_sci_msg_req_fwl_change_owner_info - Request change firewall owner
 *
 * @hdr:		Generic Header
 *
 * @fwl_id:		Firewall ID in question
 * @region:		Region or channel number if applicable
 * @owner_index:	New owner index to transfer ownership to
 */
struct ti_sci_msg_req_fwl_change_owner_info {
	struct ti_sci_msg_hdr hdr;
	uint16_t fwl_id;
	uint16_t region;
	uint8_t owner_index;
} __packed;

/**
 * struct ti_sci_msg_resp_fwl_change_owner_info - Response for change
 *						  firewall owner
 *
 * @hdr:		Generic Header
 *
 * @fwl_id:		Firewall ID specified in request
 * @region:		Region or channel number specified in request
 * @owner_index:	Owner index specified in request
 * @owner_privid:	New owner priv-ID returned by DMSC.
 * @owner_permission_bits:	New owner permission bits returned by DMSC.
 */
struct ti_sci_msg_resp_fwl_change_owner_info {
	struct ti_sci_msg_hdr hdr;
	uint16_t fwl_id;
	uint16_t region;
	uint8_t owner_index;
	uint8_t owner_privid;
	uint16_t owner_permission_bits;
} __packed;

/**
 * struct ti_sci_msg_sa2ul_get_dkek_req - Request for DKEK value
 * @hdr:			Generic header
 * @sa2ul_instance:		SA2UL instance number - set to 0
 * @kdf_label_len:		Length of "Label" input to KDF
 * @kdf_context_len:		Length of "Context" input to KDF
 * @kdf_label_and_context:	"Label" and "Context" bytes
 *
 * Request for TI_SCI_MSG_SA2UL_GET_DKEK
 */
struct ti_sci_msg_req_sa2ul_get_dkek {
	struct ti_sci_msg_hdr hdr;
	uint8_t sa2ul_instance;
	uint8_t kdf_label_len;
	uint8_t kdf_context_len;
#define KDF_LABEL_AND_CONTEXT_LEN_MAX 41
	uint8_t kdf_label_and_context[KDF_LABEL_AND_CONTEXT_LEN_MAX];
} __packed;

/**
 * struct ti_sci_msg_sa2ul_get_dkek_req - Response for DKEK value
 * @hdr:	Generic header
 * @dkek:	Array containing Derived KEK
 *
 * Response to request TI_SCI_MSG_SA2UL_GET_DKEK
 */
struct ti_sci_msg_resp_sa2ul_get_dkek {
	struct ti_sci_msg_hdr hdr;
#define SA2UL_DKEK_KEY_LEN 32
	uint8_t dkek[SA2UL_DKEK_KEY_LEN];
} __packed;

/**
 * struct ti_sci_msg_resp_read_otp_mmr - Request for reading extended OTP
 * @hdr:	Generic header
 * @mmr_idx:	Index of 32 bit MMR
 *
 * Request for TI_SCI_MSG_READ_OTP_MMR
 */
struct ti_sci_msg_req_read_otp_mmr {
	struct ti_sci_msg_hdr hdr;
	uint8_t mmr_idx;
} __packed;

/**
 * struct ti_sci_msg_resp_read_otp_mmr - Response for reading extended OTP
 * @hdr:	Generic header
 * @mmr_val:	Value written in the OTP
 *
 * Response to request TI_SCI_MSG_READ_OTP_MMR
 */
struct ti_sci_msg_resp_read_otp_mmr {
	struct ti_sci_msg_hdr hdr;
	uint32_t mmr_val;
} __packed;

/**
 * struct ti_sci_msg_req_write_otp_row - Request for writing Extended OTP
 * @hdr:	Generic header
 * @row_idx:		Index of the OTP row. Zero indexing
 * @row_val:		Value to be written
 * @row_mask:		Mask bits for row_val to be written
 *
 * Request for TI_SCI_MSG_WRITE_OTP_ROW
 */
struct ti_sci_msg_req_write_otp_row {
	struct ti_sci_msg_hdr hdr;
	uint8_t row_idx;
	uint32_t row_val;
	uint32_t row_mask;
} __packed;

/**
 * struct ti_sci_msg_resp_write_otp_row - Response for writing Extended OTP
 * @hdr:		Generic header
 * @row_val:		Value that is written
 *
 * Response to request TI_SCI_MSG_WRITE_OTP_ROW
 */
struct ti_sci_msg_resp_write_otp_row {
	struct ti_sci_msg_hdr hdr;
	uint32_t row_val;
} __packed;

/**
 * struct ti_sci_msg_req_lock_otp_row - Request for Lock OTP row
 * @hdr:		Generic header
 * @row_idx:		Index of the OTP row. Zero indexing
 * @hw_write_lock:	0x5A indicates row will be write protected
 * @hw_read_lock:	0x5A indicates row will be read protected
 * @row_soft_lock:	Software write lock
 *
 * Request for TI_SCI_MSG_LOCK_OTP_ROW
 */
struct ti_sci_msg_req_lock_otp_row {
	struct ti_sci_msg_hdr hdr;
	uint8_t row_idx;
	uint8_t hw_write_lock;
	uint8_t hw_read_lock;
	uint8_t row_soft_lock;
} __packed;

/**
 * struct ti_sci_msg_resp_lock_otp_row - Response for Lock OTP row
 * @hdr:	Generic header
 *
 * Response to request TI_SCI_MSG_LOCK_OTP_ROW
 */
struct ti_sci_msg_resp_lock_otp_row {
	struct ti_sci_msg_hdr hdr;
} __packed;

/**
 * \brief OTP Revision Identifiers
 */
enum tisci_otp_revision_identifier {
	/** Software Revision SBL */
	OTP_REV_ID_SBL        = 0,
	/** Software Revision SYSFW */
	OTP_REV_ID_SYSFW      = 1,
	/** Software Revision Secure Board Configuration */
	OTP_REV_ID_SEC_BRDCFG = 2,
};

/**
 * struct ti_sci_msq_req_get_swrev - Request for reading the Software Revision
 * in OTP
 * @hdr:	Generic header
 * @identifier: One of the entries from enum tisci_otp_revision_identifier
 *		(Current support only for OTP_REV_ID_SEC_BRDCFG)
 *
 * Request for TI_SCI_MSG_READ_SWREV
 */
struct ti_sci_msq_req_get_swrev {
	struct ti_sci_msg_hdr hdr;
	uint8_t identifier;
} __packed;

/**
 * struct ti_sci_msq_req_get_swrev - Response for reading the Software Revision
 * in OTP
 * @hdr:	Generic header
 * @swrev:	Decoded Sofrware Revision value from efuses
 *
 * Response for TI_SCI_MSG_READ_SWREV
 */
struct ti_sci_msq_resp_get_swrev {
	struct ti_sci_msg_hdr hdr;
	uint32_t swrev;
} __packed;

/**
 * struct ti_sci_msq_req_get_keycnt_keyrev - Request for reading the Key Count
 * and Key Revision in OTP
 * @hdr:	Generic header
 *
 * Request for TI_SCI_MSG_READ_KEYCNT_KEYREV
 */
struct ti_sci_msq_req_get_keycnt_keyrev {
	struct ti_sci_msg_hdr hdr;
} __packed;

/**
 * struct ti_sci_msq_req_get_swrev - Response for reading the Key Count and Key
 * Revision in OTP
 * @hdr:	Generic header
 * @keycnt:	Key Count integer value
 * @keyrev:	Key Revision integer value
 *
 * Response for TI_SCI_MSG_READ_SWREV
 */
struct ti_sci_msq_resp_get_keycnt_keyrev {
	struct ti_sci_msg_hdr hdr;
	uint32_t keycnt;
	uint32_t keyrev;
} __packed;
#endif
