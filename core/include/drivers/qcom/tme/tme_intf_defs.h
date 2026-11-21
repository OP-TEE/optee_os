/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_TME_TME_INTF_DEFS_H
#define DRIVERS_QCOM_TME_TME_INTF_DEFS_H

#include <compiler.h>
#include <stdint.h>

/*
 * QFPROM fuse read
 */

/* Address space of a QFPROM fuse */
enum tme_qfprom_addr_space {
	TME_QFPROM_ADDR_SPACE_RAW = 0,		/* Raw address space */
	TME_QFPROM_ADDR_SPACE_CORR,		/* Corrected address space */
	TME_QFPROM_ADDR_SPACE_MAX = 0x7FFFFFFF	/* Last entry */
};

/* Value of a qfprom_api_status that reports no error */
#define TME_QFPROM_NO_ERR		0x0U

/* A QFPROM row is read and written two 32-bit words at a time */
#define TME_QFPROM_FUSE_DATA_WORDS	2U

/* Request payload for TME_MSG_CBOR_TAG_FUSE_READ.*/
struct tme_fuse_read_req {
	/* enum tme_qfprom_addr_space: raw or corrected */
	uint32_t addr_type;
	uint32_t fuse_addr;	/* Address of the fuse to be read */
} __packed;

/* Response payload for TME_MSG_CBOR_TAG_FUSE_READ. */
struct tme_fuse_read_rsp {
	uint32_t status;			/* TME handler status */
	/* Fuse value as read from the QFPROM, low word first */
	uint32_t fuse_data[TME_QFPROM_FUSE_DATA_WORDS];
	uint32_t qfprom_api_status;		/* QFPROM status value */
} __packed;

/*
 * QFPROM fuse write
 */

/* Maximum number of rows TME FW accepts in one FUSE_WRITE_MULTIPLE request. */
#define TME_MAX_FUSE_WRITE_REQ		64U

/* Placeholder written to the caller's qfprom_api_status before the exchange */
#define TME_QFPROM_STATUS_UNSET		0xFFFFFFFFU

/*
 * One row of a fuse-write request.
 *
 * WARNING: fuses are one-time-programmable.  A set bit in data[] permanently
 * blows that fuse bit on real silicon; it cannot be cleared afterwards.  An
 * all-zero data[] blows nothing and is the only non-destructive value.
 */
struct tme_fuse {
	uint32_t addr;				/* Address of the row */
	uint32_t data[TME_QFPROM_FUSE_DATA_WORDS]; /* Value, low word first */
} __packed;

/* Request payload for TME_MSG_CBOR_TAG_FUSE_WRITE_MULTIPLE. */
struct tme_fuse_write_multiple_req {
	/* Rows to write */
	struct tme_fuse fuse_array[TME_MAX_FUSE_WRITE_REQ];
	uint32_t fuse_array_len;	/* Valid entries in fuse_array */
} __packed;

/* Request payload for TME_MSG_CBOR_TAG_FUSE_WRITE_MULTIPLE. */
struct tme_fuse_write_multiple_rsp {
	uint32_t status;	/* TME status, TME_QFPROM_NO_ERR if OK */
	uint32_t addr_err;	/* Address/error detail of the QFPROM driver */
} __packed;

/*
 * QFPROM configuration register write
 */

/* Register identifiers accepted by TME_MSG_CBOR_TAG_WRITE_CONFIG_REGISTER. */
enum tme_config_register_id {
	QFPROM_BIST_CTRL = 1,
	QFPROM_WRITE_DISABLE_STICKY_BIT0,
	QFPROM_WRITE_DISABLE_STICKY_BIT1,
	TME_WRITE_CONFIG_REGISTER_MAX = 0xFF
};

/* Request payload for TME_MSG_CBOR_TAG_WRITE_CONFIG_REGISTER. */
struct tme_write_config_register_req {
	/* enum tme_config_register_id: register to write */
	uint8_t id;
	uint32_t value;		/* Value to write into the register */
} __packed;

/* Response payload for TME_MSG_CBOR_TAG_WRITE_CONFIG_REGISTER. */
struct tme_write_config_register_rsp {
	uint32_t status;	/* TME handler status, 0 if OK */
} __packed;

/*
 * Antirollback version update
 */

/*
 * Response payload for TME_MSG_CBOR_TAG_UPDATE_ROLLBACK_VERSION.
 *
 * There is no matching request struct: the message carries an empty payload.
 * TME FW already holds the image versions recorded during authentication and
 * decides for itself which antirollback fuses to blow, so the caller has
 * nothing to send.
 */
struct tme_update_rollback_version_rsp {
	uint32_t status;	/* TME handler status, 0 if OK */
	uint32_t err_addr;	/* Address of the failing fuse if status != 0 */
} __packed;

/*
 * Get Antirollback version
 */

/* Used for oem_is_valid and qti_is_valid */
#define TME_ARB_VERSION_IS_INVALID	0U
#define TME_ARB_VERSION_IS_VALID	1U

/* Request payload for TME_MSG_CBOR_TAG_GET_ARB_VERSION. */
struct tme_get_arb_version_req {
	uint32_t sw_id;		/* Software image to get the ARB version of */
} __packed;

/* Response payload for TME_MSG_CBOR_TAG_GET_ARB_VERSION. */
struct tme_get_arb_version_rsp {
	uint8_t oem_version;	/* OEM ARB version, if oem_is_valid */
	uint8_t qti_version;	/* QTI ARB version, if qti_is_valid */
	uint8_t oem_is_valid;
	uint8_t qti_is_valid;
} __packed;

#endif /* DRIVERS_QCOM_TME_TME_INTF_DEFS_H */
