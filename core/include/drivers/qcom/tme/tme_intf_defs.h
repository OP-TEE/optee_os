/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef DRIVERS_QCOM_TME_TME_INTF_DEFS_H
#define DRIVERS_QCOM_TME_TME_INTF_DEFS_H

#include <compiler.h>
#include <stdint.h>

/* Address space of a QFPROM fuse */
typedef enum {
	TME_QFPROM_ADDR_SPACE_RAW = 0,		/* Raw address space */
	TME_QFPROM_ADDR_SPACE_CORR,		/* Corrected address space */
	TME_QFPROM_ADDR_SPACE_MAX = 0x7FFFFFFF	/* Last entry */
} TmeQfpromAddrSpace_t;

/* Value of a qfprom_api_status that reports no error */
#define TME_QFPROM_NO_ERR		0x0U

/* A QFPROM row is read and written two 32-bit words at a time */
#define TME_QFPROM_FUSE_DATA_WORDS	2U

/*
 * Fuse Read Structure
 */
typedef struct {
	uint32_t addr_type;	/* TmeQfpromAddrSpace_t: raw or corrected */
	uint32_t fuse_addr;	/* Address of the fuse to be read */
} __packed tmeFuseReadReq_t;

/*
 * The order of the fields is the one of the TME firmware: the status comes
 * first, then the row, then the status of the QFPROM driver. Do not reorder
 * them, the size of the structure would stay the same.
 */
typedef struct {
	uint32_t status;			/* TME handler status */
	/* Fuse value as read from the QFPROM, low word first */
	uint32_t fuse_data[TME_QFPROM_FUSE_DATA_WORDS];
	uint32_t qfprom_api_status;		/* QFPROM status value */
} __packed tmeFuseReadRsp_t;

/*
 * Fuse Write Multiple Structure
 */

/* Number of rows of a fuse write request, it is always sent in full */
#define TME_MAX_FUSE_WRITE_REQ		64U

/* qfprom_api_status of a fuse write before the TME has answered */
#define TME_QFPROM_STATUS_UNSET		0xFFFFFFFFU

/*
 * One row of a fuse write request. A set bit of data[] blows that fuse bit for
 * good, an all-zero data[] blows nothing.
 */
typedef struct {
	uint32_t addr;				/* Address of the row */
	uint32_t data[TME_QFPROM_FUSE_DATA_WORDS]; /* Value, low word first */
} __packed TMEFuse_t;

/* The TME rejects a request shorter than the whole structure */
typedef struct {
	TMEFuse_t fuse_array[TME_MAX_FUSE_WRITE_REQ];	/* Rows to write */
	uint32_t fuse_array_len;	/* Valid entries in fuse_array */
} __packed tmeFuseWriteMultipleReq_t;

typedef struct {
	uint32_t status;	/* TME status, TME_QFPROM_NO_ERR if OK */
	uint32_t addr_err;	/* Address/error detail of the QFPROM driver */
} __packed tmeFuseWriteMultipleRsp_t;

/*
 * Write Config Register Structure
 */

/* Registers that can be written, the values are the ones of the TME firmware */
typedef enum {
	QFPROM_BIST_CTRL = 1,
	QFPROM_WRITE_DISABLE_STICKY_BIT0,
	QFPROM_WRITE_DISABLE_STICKY_BIT1,
	TME_WRITE_CONFIG_REGISTER_MAX = 0xFF	/* Last entry */
} tmeConfigRegisterId_e;

typedef struct {
	uint8_t id;		/* tmeConfigRegisterId_e: register to write */
	uint32_t value;		/* Value to write into the register */
} __packed tmeWriteConfigRegisterReq_t;

typedef struct {
	uint32_t status;	/* TME handler status, 0 if OK */
} __packed tmeWriteConfigRegisterRsp_t;

/*
 * Update Rollback Version Structure. There is no request structure, the
 * request has an empty payload: the TME knows the versions it recorded.
 */
typedef struct {
	uint32_t status;	/* TME handler status, 0 if OK */
	uint32_t err_addr;	/* Address of the failing fuse if status != 0 */
} __packed tmeUpdateRollbackVersionRsp_t;

#endif /* DRIVERS_QCOM_TME_TME_INTF_DEFS_H */
