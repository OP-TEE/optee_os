/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __DRIVERS_TPM2_CMD_H
#define __DRIVERS_TPM2_CMD_H

#include <compiler.h>
#include <io.h>
#include <stdint.h>
#include <utee_defines.h>

/* TPM Command Response structure */
struct tpm2_cmd_hdr {
	uint16_t tag;
	uint32_t size;	/* size of command/response */
	uint32_t code;	/* command code or response code */
} __packed;

#define TPM2_HDR_LEN	sizeof(struct tpm2_cmd_hdr)

/*
 * A command indicates the operation to be performed by the TPM. It contains
 * a command header followed by command dependent data which may include
 * handles, authorization area and command dependent parameters.
 */
struct tpm2_cmd {
	struct tpm2_cmd_hdr hdr;
	uint8_t data[];
} __packed;

/* Returns total number of octets in the command/response starting from tag */
static inline uint16_t tpm2_cmd_len(struct tpm2_cmd *cmd)
{
	return TEE_U32_FROM_BIG_ENDIAN(cmd->hdr.size);
}

static inline uint16_t tpm2_cmd_code(struct tpm2_cmd *cmd)
{
	return TEE_U32_FROM_BIG_ENDIAN(cmd->hdr.code);
}

static inline uint16_t tpm2_ret_code(struct tpm2_cmd *cmd)
{
	return TEE_U32_FROM_BIG_ENDIAN(cmd->hdr.code);
}

#endif	/* __DRIVERS_TPM2_CMD_H */

