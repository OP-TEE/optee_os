// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <drivers/tpm2_chip.h>
#include <drivers/tpm2_cmd.h>
#include <io.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <string.h>
#include <tpm2.h>
#include <trace.h>

static void tpm2_cmd_init_hdr(void *buf, uint32_t len, uint16_t tag,
			      uint32_t cmd_code)
{
	struct tpm2_cmd *cmd = (struct tpm2_cmd *)buf;

	assert(len >= sizeof(*cmd));

	put_unaligned_be16(&cmd->hdr.tag, tag);
	put_unaligned_be32(&cmd->hdr.size, sizeof(struct tpm2_cmd_hdr));
	put_unaligned_be32(&cmd->hdr.code, cmd_code);
}

static void tpm2_cmd_add(void *buf, uint32_t len, uint8_t *val,
			 uint32_t val_len)
{
	struct tpm2_cmd *cmd = (struct tpm2_cmd *)buf;
	uint32_t cmd_len = tpm2_cmd_len(cmd);

	assert(len >= (cmd_len + val_len));

	memcpy(&cmd->data[cmd_len - sizeof(struct tpm2_cmd_hdr)], val, val_len);

	cmd_len += val_len;
	put_unaligned_be32(&cmd->hdr.size, cmd_len);
}

static void tpm2_cmd_add_u8(void *buf, uint32_t len, uint8_t val)
{
	tpm2_cmd_add(buf, len, &val, 1);
}

static void tpm2_cmd_add_u16(void *buf, uint32_t len, uint16_t val)
{
	uint16_t val_be = TEE_U16_FROM_BIG_ENDIAN(val);

	tpm2_cmd_add(buf, len, (uint8_t *)&val_be, 2);
}

static void tpm2_cmd_add_u32(void *buf, uint32_t len, uint32_t val)
{
	uint32_t val_be = TEE_U32_FROM_BIG_ENDIAN(val);

	tpm2_cmd_add(buf, len, (uint8_t *)&val_be, 4);
}

/* Timeout has been picked up from Table 17 - Command Timing */
static uint32_t tpm2_get_cmd_duration(uint32_t cmd_code)
{
	switch (cmd_code) {
	case TPM2_CC_STARTUP:
	case TPM2_CC_PCR_EXTEND:
	case TPM2_CC_GET_CAPABILITY:
		return TPM2_CMD_DURATION_MEDIUM;
	case TPM2_CC_SELFTEST:
	case TPM2_CC_NV_READ:
		return TPM2_CMD_DURATION_LONG;
	default:
		return TPM2_CMD_DURATION_DEFAULT;
	}
}

static enum tpm2_result tpm2_transmit(void *buf, uint32_t bufsz, void *resp,
				      uint32_t *len)
{
	uint32_t cmd_duration = 0;
	enum tpm2_result rc = TPM2_OK;
	uint32_t err_code = 0;

	if (!buf || !resp || !len || (len && !*len))
		return TPM2_ERR_INVALID_ARG;

	if (bufsz < tpm2_cmd_len(buf))
		return TPM2_ERR_INVALID_ARG;

	DHEXDUMP(buf, tpm2_cmd_len(buf));

	rc = tpm2_chip_send(buf, bufsz);
	if (rc)
		return rc;

	cmd_duration = tpm2_get_cmd_duration(tpm2_cmd_code(buf));

	rc = tpm2_chip_recv(resp, len, cmd_duration);
	if (rc)
		return rc;

	err_code = tpm2_ret_code(resp);
	if (err_code) {
		EMSG("Command Error code %" PRIx32, err_code);
		rc = TPM2_ERR_CMD;
	}

	DHEXDUMP(resp, tpm2_cmd_len(resp));

	return rc;
}

enum tpm2_result tpm2_startup(uint16_t mode)
{
	uint8_t buf[16] = { };
	uint32_t buf_len = sizeof(buf);
	uint8_t resp_buf[TPM2_HDR_LEN] = { };
	uint32_t resp_len = sizeof(resp_buf);
	enum tpm2_result rc = TPM2_OK;

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS, TPM2_CC_STARTUP);
	tpm2_cmd_add_u16(buf, buf_len, mode);

	rc = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			   &resp_len);
	if (rc == TPM2_ERR_SHORT_BUFFER)
		EMSG("Increase size of response buffer to %#" PRIx32, resp_len);

	return rc;
}

enum tpm2_result tpm2_selftest(uint8_t full)
{
	uint8_t buf[16] = { };
	uint32_t buf_len = sizeof(buf);
	uint8_t resp_buf[TPM2_HDR_LEN] = { };
	uint32_t resp_len = sizeof(resp_buf);
	enum tpm2_result rc = TPM2_OK;

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS, TPM2_CC_SELFTEST);
	tpm2_cmd_add_u8(buf, buf_len, full);

	rc = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			   &resp_len);
	if (rc == TPM2_ERR_SHORT_BUFFER)
		EMSG("Increase size of response buffer to %#" PRIx32, resp_len);

	return rc;
}
