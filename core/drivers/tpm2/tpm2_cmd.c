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
	enum tpm2_result ret = TPM2_OK;
	uint32_t err_code = 0;

	if (!buf || !resp || !len || (len && !*len))
		return TPM2_ERR_INVALID_ARG;

	if (bufsz < tpm2_cmd_len(buf))
		return TPM2_ERR_INVALID_ARG;

	DHEXDUMP(buf, tpm2_cmd_len(buf));

	ret = tpm2_chip_send(buf, bufsz);
	if (ret)
		return ret;

	cmd_duration = tpm2_get_cmd_duration(tpm2_cmd_code(buf));

	ret = tpm2_chip_recv(resp, len, cmd_duration);
	if (ret)
		return ret;

	err_code = tpm2_ret_code(resp);
	if (err_code) {
		EMSG("Command Error code %" PRIx32, err_code);
		ret = TPM2_ERR_CMD;
	}

	DHEXDUMP(resp, tpm2_cmd_len(resp));

	return ret;
}

enum tpm2_result tpm2_startup(uint16_t mode)
{
	uint8_t buf[16] = { };
	uint32_t buf_len = sizeof(buf);
	uint8_t resp_buf[TPM2_HDR_LEN] = { };
	uint32_t resp_len = sizeof(resp_buf);
	enum tpm2_result ret = TPM2_OK;

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS, TPM2_CC_STARTUP);
	tpm2_cmd_add_u16(buf, buf_len, mode);

	ret = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			    &resp_len);
	if (ret == TPM2_ERR_SHORT_BUFFER)
		EMSG("Increase size of response buffer to %#" PRIx32, resp_len);

	return ret;
}

enum tpm2_result tpm2_selftest(uint8_t full)
{
	uint8_t buf[16] = { };
	uint32_t buf_len = sizeof(buf);
	uint8_t resp_buf[TPM2_HDR_LEN] = { };
	uint32_t resp_len = sizeof(resp_buf);
	enum tpm2_result ret = TPM2_OK;

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS, TPM2_CC_SELFTEST);
	tpm2_cmd_add_u8(buf, buf_len, full);

	ret = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			    &resp_len);
	if (ret == TPM2_ERR_SHORT_BUFFER)
		EMSG("Increase size of response buffer to %#" PRIx32, resp_len);

	return ret;
}

enum tpm2_result tpm2_get_capability(uint32_t capability, uint32_t property,
				     uint32_t prop_cnt, void *prop,
				     uint32_t *prop_len)
{
	uint8_t buf[32] = { };
	uint32_t buf_len = sizeof(buf);
	uint8_t *resp_buf = NULL;
	uint32_t resp_len = 256;
	uint32_t prop_offset = 0;
	enum tpm2_result ret = TPM2_OK;

	if (!prop || !prop_len || !*prop_len)
		return TPM2_ERR_INVALID_ARG;

	resp_buf = malloc(resp_len);
	if (!resp_buf)
		return TPM2_ERR_GENERIC;

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS,
			  TPM2_CC_GET_CAPABILITY);
	tpm2_cmd_add_u32(buf, buf_len, capability);
	tpm2_cmd_add_u32(buf, buf_len, property);
	tpm2_cmd_add_u32(buf, buf_len, prop_cnt);

	ret = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			    &resp_len);
	if (ret)
		goto out;

	resp_len = tpm2_cmd_len((struct tpm2_cmd *)resp_buf);

	/*
	 * Response include
	 * tpm2_cmd_hdr [10 bytes]
	 * TPM1_YES_NO (byte)
	 * capability (uin32_t)
	 * capability data [ This is the property data to be returned ]
	 */
	prop_offset = sizeof(struct tpm2_cmd_hdr) + sizeof(uint8_t) +
		      sizeof(uint32_t);

	if (*prop_len >= resp_len - prop_offset) {
		memcpy(prop, &resp_buf[prop_offset], resp_len - prop_offset);
	} else {
		EMSG("Response Buffer size for property too small");
		ret = TPM2_ERR_SHORT_BUFFER;
	}

	*prop_len = resp_len - prop_offset;
out:
	free(resp_buf);
	return ret;
}

enum tpm2_result tpm2_pcr_read(uint8_t pcr_idx, uint16_t alg, void *digest,
			       uint32_t *digest_len)
{
	uint8_t buf[32] = { };
	uint8_t *resp_buf = NULL;
	uint32_t buf_len = sizeof(buf);
	uint32_t resp_len = 0;
	uint32_t alg_len = 0;
	uint32_t count = 1;
	uint32_t digest_offset = 0;
	uint8_t *pcr_select = 0;
	uint8_t pcr_select_idx = 0;
	uint8_t pcr_select_size = 0;
	struct tpm2_caps caps = { };
	enum tpm2_result ret = TPM2_OK;
	struct tpml_digest *resp_dgst = NULL;
	struct tpm2b_digest *dgst = resp_dgst->digest;

	if (!digest || !digest_len)
		return TPM2_ERR_INVALID_ARG;

	ret = tpm2_chip_get_caps(&caps);
	if (ret)
		return ret;

	if (pcr_idx >= caps.num_pcrs || !tpm2_chip_is_active_bank(alg))
		return TPM2_ERR_INVALID_ARG;

	alg_len = tpm2_get_alg_len(alg);
	if (*digest_len < alg_len)
		return TPM2_ERR_INVALID_ARG;

	/*
	 * pcr_select is an array of octets where the octet contains the bit
	 * corresponding to a specific PCR. Octet index is found by dividing the
	 * PCR number by 8.
	 */
	pcr_select_idx = pcr_idx >> 3;

	/*
	 * pcr_select_size indicates the number of octets in pcr_select. It's
	 * minimum value is available in caps structure.
	 */
	pcr_select_size = MAX(pcr_select_idx, caps.pcr_select_min);

	/* Double check - the size shouldn't exceed TPM2_PCR_SELECT_MAX */
	if (pcr_select_size > TPM2_PCR_SELECT_MAX)
		return TPM2_ERR_INVALID_ARG;

	pcr_select = calloc(pcr_select_size, sizeof(*pcr_select));
	if (!pcr_select)
		return TPM2_ERR_GENERIC;

	pcr_select[pcr_select_idx] = BIT(pcr_idx % 8);

	/* Create the PCR Read command */
	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_NO_SESSIONS,
			  TPM2_CC_PCR_READ);
	/* TPML_PCR_SELECTION */
	tpm2_cmd_add_u32(buf, buf_len, count);
	tpm2_cmd_add_u16(buf, buf_len, alg);
	tpm2_cmd_add_u8(buf, buf_len, pcr_select_size);
	tpm2_cmd_add(buf, buf_len, pcr_select, pcr_select_size);

	free(pcr_select);

	/* Response includes:
	 * TPM Command header
	 * PCR update counter (uint32_t)
	 * TPML PCR Selection
	 * TPML DIGEST
	 */
	digest_offset = sizeof(struct tpm2_cmd_hdr) + sizeof(uint32_t) +
			offsetof(struct tpml_pcr_selection, pcr_selections) +
			offsetof(struct tpms_pcr_selection, pcr_select) +
			pcr_select_size;
	resp_len = digest_offset + sizeof(struct tpml_digest);

	resp_buf = malloc(resp_len);
	if (!resp_buf)
		return TPM2_ERR_GENERIC;

	ret = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			    &resp_len);
	if (ret)
		goto out;

	resp_len = tpm2_cmd_len((struct tpm2_cmd *)resp_buf);

	DHEXDUMP(resp_buf, tpm2_cmd_len((struct tpm2_cmd *)resp_buf));

	if (digest_offset > resp_len) {
		ret = TPM2_ERR_GENERIC;
		goto out;
	}

	resp_dgst = (struct tpml_digest *)&resp_buf[digest_offset];
	dgst = resp_dgst->digest;

	/* We had requested for only 1 digest so expected count is 1 */
	if (get_be32(&resp_dgst->count) != 1) {
		ret = TPM2_ERR_GENERIC;
		goto out;
	}

	if (get_be16(&dgst->size) != alg_len) {
		ret = TPM2_ERR_GENERIC;
		goto out;
	}

	memcpy(digest, dgst->buffer, alg_len);

	*digest_len = alg_len;
out:
	free(resp_buf);
	return ret;
}

static enum tpm2_result tpm2_add_password_auth_cmd(uint8_t *buf,
						   uint32_t buf_len,
						   uint8_t *passwd,
						   uint32_t pass_sz)
{
	struct tpms_auth_command cmd = { };
	uint32_t auth_sz = 0;

	if (pass_sz && (pass_sz > sizeof(cmd.hmac.buffer) || !passwd))
		return TPM2_ERR_INVALID_ARG;

	cmd.handle = TPM_RS_PW;
	/* For password authorization, nonce is empty buffer */
	cmd.nonce.size = 0;
	/* Password session is always available so has no effect */
	cmd.session_attributes = 0;
	cmd.hmac.size = pass_sz;

	auth_sz = sizeof(cmd.handle) + sizeof(cmd.nonce.size) +
		  sizeof(cmd.session_attributes) + sizeof(cmd.hmac.size) +
		  cmd.hmac.size;

	tpm2_cmd_add_u32(buf, buf_len, auth_sz);
	tpm2_cmd_add_u32(buf, buf_len, cmd.handle);
	tpm2_cmd_add_u16(buf, buf_len, cmd.nonce.size);
	tpm2_cmd_add_u8(buf, buf_len, cmd.session_attributes);
	tpm2_cmd_add_u16(buf, buf_len, cmd.hmac.size);
	if (cmd.hmac.size)
		tpm2_cmd_add(buf, buf_len, passwd, pass_sz);

	return TPM2_OK;
}

enum tpm2_result tpm2_pcr_extend(uint8_t pcr_idx, uint16_t alg, void *digest,
				 uint32_t digest_len)
{
	void *buf = NULL;
	uint32_t buf_len = 128;
	uint8_t *resp_buf = NULL;
	uint32_t resp_len = 256;
	uint32_t alg_len = 0;
	uint32_t count = 1;
	struct tpm2_caps caps = { };
	enum tpm2_result ret = TPM2_OK;

	if (!digest)
		return TPM2_ERR_INVALID_ARG;

	ret = tpm2_chip_get_caps(&caps);
	if (ret)
		return ret;

	if (pcr_idx >= caps.num_pcrs || !tpm2_chip_is_active_bank(alg))
		return TPM2_ERR_INVALID_ARG;

	alg_len = tpm2_get_alg_len(alg);
	if (digest_len < alg_len)
		return TPM2_ERR_INVALID_ARG;

	/* CMD size will not exceed 128 bytes */
	buf = malloc(buf_len);
	if (!buf)
		return TPM2_ERR_GENERIC;

	resp_buf = malloc(resp_len);
	if (!resp_buf) {
		free(buf);
		return TPM2_ERR_GENERIC;
	}

	tpm2_cmd_init_hdr(buf, buf_len, TPM2_ST_SESSIONS, TPM2_CC_PCR_EXTEND);

	/* PCR Handle */
	tpm2_cmd_add_u32(buf, buf_len, pcr_idx);

	/* Add NULL authorization structure */
	ret = tpm2_add_password_auth_cmd(buf, buf_len, NULL, 0);
	if (ret)
		goto out;

	/*
	 * Add TPML_DIGEST_VALUES structure, we are adding
	 * a single digest.
	 */
	tpm2_cmd_add_u32(buf, buf_len, count);
	tpm2_cmd_add_u16(buf, buf_len, alg);
	tpm2_cmd_add(buf, buf_len, digest, digest_len);

	ret = tpm2_transmit(buf, tpm2_cmd_len((struct tpm2_cmd *)buf), resp_buf,
			    &resp_len);
	if (ret)
		goto out;

	DHEXDUMP(resp_buf, tpm2_cmd_len((struct tpm2_cmd *)resp_buf));
out:
	free(resp_buf);
	free(buf);

	return ret;
}
