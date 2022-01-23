/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TPM2_H__
#define __TPM2_H__

#include <stdint.h>
#include <types_ext.h>
#include <util.h>

#define TPM2_REG_SIZE 0x5000

#define TPM2_HDR_LEN 10

#define TPM2_ACCESS(v)		SHIFT_U32((v), 12)
#define TPM2_INT_ENABLE(v)	(SHIFT_U32((v), 12) | BIT(3))
#define TPM2_STS(v)		(SHIFT_U32((v), 12) | SHIFT_U32(3, 3))
#define TPM2_DATA_FIFO(v)	(SHIFT_U32((v), 12) | SHIFT_U32(9, 2))
#define TPM2_DID_VID(v)		(SHIFT_U32((v), 12) | SHIFT_U32(0xF, 8))
#define TPM2_RID(v)		(SHIFT_U32((v), 12) | SHIFT_U32(0x3C1, 2))

enum tpm2_int_flags {
	TPM2_INT_DATA_AVAIL_INT = BIT(0),
	TPM2_INT_STS_VALID_INT = BIT(1),
	TPM2_INT_LOCALITY_CHANGE_INT = BIT(2),
	TPM2_INT_CMD_READY_INT = BIT(7),
	TPM2_GLOBAL_INT_ENABLE = BIT(31),
};

/*
 * Based on:
 * linux/errno.h (very loosely)
 * TCG_TPM2_r1p59_Part4_SuppRoutines_code_pub (Table 2:16)
 */
enum tpm2_result {
	TPM2_OK = 0,

	TPM2_ERR_GENERIC = 1,
	TPM2_ERR_INVALID_ARG = 2,
	TPM2_ERR_BUSY = 3,
	TPM2_ERR_TIMEOUT = 4,
	TPM2_ERR_IO = 5,
	TPM2_ERR_ARG_LIST_TOO_LONG = 6,

	TPM2_ERR_BAD_TAG = SHIFT_U32(0xF, 1),

	TPM2_ERR_FMT1 = BIT(7),
	TPM2_ERR_HASH = TPM2_ERR_FMT1 + 3,
	TPM2_ERR_VALUE = TPM2_ERR_FMT1 + 4,
	TPM2_ERR_HANDLE = TPM2_ERR_FMT1 + 0xB,
	TPM2_ERR_SIZE = TPM2_ERR_FMT1 + 0x15,
	TPM2_ERR_BAD_AUTH = TPM2_ERR_FMT1 + 0x22,

	TPM2_ERR_VER1 = BIT(8),
	TPM2_ERR_INIT = TPM2_ERR_VER1,
	TPM2_ERR_FAILURE = TPM2_ERR_VER1 + 1,
	TPM2_ERR_DISABLED = TPM2_ERR_VER1 + 0x20,
	TPM2_ERR_AUTH_MISSING = TPM2_ERR_VER1 + 0x25,
	TPM2_ERR_CMD_CODE = TPM2_ERR_VER1 + 0x43,
	TPM2_ERR_AUTHSIZE = TPM2_ERR_VER1 + 0x44,
	TPM2_ERR_AUTH_CONTEXT = TPM2_ERR_VER1 + 0x45,
	TPM2_ERR_NV_DEFINED = TPM2_ERR_VER1 + 0x4c,
	TPM2_ERR_NEEDS_TEST = TPM2_ERR_VER1 + 0x53,

	TPM2_ERR_WARN = SHIFT_U32(9, 8),
	TPM2_ERR_TESTING = TPM2_ERR_WARN + 0xA,
	TPM2_ERR_REF_H0 = TPM2_ERR_WARN + 0x10,
	TPM2_ERR_LOCKOUT = TPM2_ERR_WARN + 0x21,
};

enum tpm2_timeout {
	TPM2_TIMEOUT_MS = 5,
	TPM2_TIMEOUT_SHORT_MS = 750,
	TPM2_TIMEOUT_LONG_MS = 2000,
};

enum {
	TPM2_ACCESS_ESTABLISHMENT = BIT(0),
	TPM2_ACCESS_REQUEST_USE = BIT(1),
	TPM2_ACCESS_REQUEST_PENDING = BIT(2),
	TPM2_ACCESS_ACTIVE_LOCALITY = BIT(5),
	TPM2_ACCESS_VALID = BIT(7),
};

enum {
	TPM2_STS_RESPONSE_RETRY = BIT(1),
	TPM2_STS_SELF_TEST_DONE = BIT(2),
	TPM2_STS_DATA_EXPECT = BIT(3),
	TPM2_STS_DATA_AVAIL = BIT(4),
	TPM2_STS_GO = BIT(5),
	TPM2_STS_READ_ZERO = 0x23,
	TPM2_STS_COMMAND_READY = BIT(6),
	TPM2_STS_VALID = BIT(7),
	TPM2_STS_COMMAND_CANCEL = BIT(24),
	TPM2_STS_RESE_TESTABLISMENT_BIT = BIT(25),
	TPM2_STS_FAMILY_TPM2 = BIT(26),
	TPM2_STS_FAMILY_MASK = SHIFT_U32(3, 26),
	TPM2_STS_BURST_COUNT_MASK = SHIFT_U32(0xFFFF, 8),
};

enum {
	TPM2_CMD_COUNT_OFFSET = BIT(1),
	TPM2_CMD_ORDINAL_OFFSET = SHIFT_U32(3, 1),
	TPM2_MAX_BUF_SIZE = 1260,
};

struct tpm2_chip {
	const struct tpm2_ops *ops;
	int32_t locality;
	uint32_t timeout_a;
	uint32_t timeout_b;
	uint32_t timeout_c;
	uint32_t timeout_d;
	uint32_t type;
	uint32_t vend_dev;
	uint8_t rid;
	bool is_open;
};

struct tpm2_ops {
	enum tpm2_result (*rx32)(struct tpm2_chip *chip, uint32_t adr,
				 uint32_t *buf);
	enum tpm2_result (*tx32)(struct tpm2_chip *chip, uint32_t adr,
				 uint32_t val);
	enum tpm2_result (*rx8)(struct tpm2_chip *chip, uint32_t adr,
				uint16_t len, uint8_t *buf);
	enum tpm2_result (*tx8)(struct tpm2_chip *chip, uint32_t adr,
				uint16_t len, uint8_t *buf);
};

uint32_t tpm2_convert2be(uint8_t *buf);
enum tpm2_result tpm2_init(struct tpm2_chip *chip);
enum tpm2_result tpm2_end(struct tpm2_chip *chip);
enum tpm2_result tpm2_open(struct tpm2_chip *chip);
enum tpm2_result tpm2_close(struct tpm2_chip *chip);
enum tpm2_result tpm2_tx(struct tpm2_chip *chip, uint8_t *buf, uint32_t len);
enum tpm2_result tpm2_rx(struct tpm2_chip *chip, uint8_t *buf, uint32_t len);

#endif	/* __TPM2_H__ */

