/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "handle.h"
#include "pkcs11_token.h"
#include "sks_helpers.h"

/* Provide 3 slots/tokens */
#define TOKEN_COUNT	3

/* Static allocation of tokens runtime instances (reset to 0 at load) */
struct ck_token ck_token[TOKEN_COUNT];

/* Static allocation of tokens runtime instances */
struct ck_token *get_token(unsigned int token_id)
{
	if (token_id > TOKEN_COUNT)
		return NULL;

	return &ck_token[token_id];
}

unsigned int get_token_id(struct ck_token *token)
{
	int count;

	for (count = 0; count < TOKEN_COUNT; count++)
		if (token == &ck_token[count])
			return count;

	TEE_Panic(0);
	return 0;
}

static int pkcs11_token_init(unsigned int id)
{
	struct ck_token *token = get_token(id);

	if (!token)
		return 1;

	if (token->login_state != PKCS11_TOKEN_STATE_INVALID)
		return 0;

	TEE_MemFill(token->label, '*', SKS_TOKEN_LABEL_SIZE);

	/*
	 * Not supported:
	 *   SKS_TOKEN_FULLY_RESTORABLE
	 * TODO: check these:
	 *   SKS_TOKEN_HAS_CLOCK => related to TEE time secure level
	 */
	token->flags = SKS_TOKEN_SO_PIN_TO_CHANGE | \
			 SKS_TOKEN_USR_PIN_TO_CHANGE | \
			 SKS_TOKEN_HAS_RNG | \
			 SKS_TOKEN_IS_READ_ONLY | \
			 SKS_TOKEN_REQUIRE_LOGIN | \
			 SKS_TOKEN_CAN_DUAL_PROC;

	/* Initialize the token runtime state */
	token->login_state = PKCS11_TOKEN_STATE_PUBLIC_SESSIONS;
	token->session_state = PKCS11_TOKEN_STATE_SESSION_NONE;

	return 0;
}

/*
 * Initialization routine for the trsuted application.
 */
int pkcs11_init(void)
{
	unsigned int id;

	for (id = 0; id < TOKEN_COUNT; id++)
		if (pkcs11_token_init(id))
			return 1;

	return 0;
}

uint32_t ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const size_t out_size = sizeof(uint32_t) * TOKEN_COUNT;
	uint32_t *id;
	unsigned int n;

	if (ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;
		return SKS_SHORT_BUFFER;
	}

	for (id = out->memref.buffer, n = 0; n < TOKEN_COUNT; n++, id++)
		*id = (uint32_t)n;

	out->memref.size = out_size;
	return SKS_OK;
}

uint32_t ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const char desc[] = SKS_CRYPTOKI_SLOT_DESCRIPTION;
	const char manuf[] = SKS_CRYPTOKI_SLOT_MANUFACTURER;
	const char hwver[2] = SKS_CRYPTOKI_SLOT_HW_VERSION;
	const char fwver[2] = SKS_CRYPTOKI_SLOT_FW_VERSION;
	struct sks_ck_slot_info *info;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (ctrl->memref.size != sizeof(token_id))
		return SKS_BAD_PARAM;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	if (out->memref.size < sizeof(struct sks_ck_slot_info)) {
		out->memref.size = sizeof(struct sks_ck_slot_info);
		return SKS_SHORT_BUFFER;
	}

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	/* TODO: prevent crash on unaligned buffers */
	info = (void *)out->memref.buffer;

	TEE_MemFill(info, 0, sizeof(*info));

	PADDED_STRING_COPY(info->slotDescription, desc);
	PADDED_STRING_COPY(info->manufacturerID, manuf);

	info->flags |= SKS_TOKEN_PRESENT;
	info->flags |= SKS_TOKEN_REMOVABLE;
	info->flags &= ~SKS_TOKEN_HW;		/* are we a HW or SW slot? */

	TEE_MemMove(&info->hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info->firmwareVersion, &fwver, sizeof(fwver));

	out->memref.size = sizeof(struct sks_ck_slot_info);

	return SKS_OK;
}

uint32_t ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const char manuf[] = SKS_CRYPTOKI_TOKEN_MANUFACTURER;
	const char sernu[] = SKS_CRYPTOKI_TOKEN_SERIAL_NUMBER;
	const char model[] = SKS_CRYPTOKI_TOKEN_MODEL;
	const char hwver[] = SKS_CRYPTOKI_TOKEN_HW_VERSION;
	const char fwver[] = SKS_CRYPTOKI_TOKEN_FW_VERSION;
	struct sks_ck_token_info info;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (ctrl->memref.size != sizeof(token_id))
		return SKS_BAD_PARAM;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	if (out->memref.size < sizeof(struct sks_ck_token_info)) {
		out->memref.size = sizeof(struct sks_ck_token_info);
		return SKS_SHORT_BUFFER;
	}

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	TEE_MemFill(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.label, token->label);
	PADDED_STRING_COPY(info.manufacturerID, manuf);
	PADDED_STRING_COPY(info.model, model);
	PADDED_STRING_COPY(info.serialNumber, sernu);

	info.flags = token->flags;

	/* TODO */
	info.ulMaxSessionCount = ~0;
	info.ulSessionCount = ~0;
	info.ulMaxRwSessionCount = ~0;
	info.ulRwSessionCount = ~0;
	/* TODO */
	info.ulMaxPinLen = 128;
	info.ulMinPinLen = 10;
	/* TODO */
	info.ulTotalPublicMemory = ~0;
	info.ulFreePublicMemory = ~0;
	info.ulTotalPrivateMemory = ~0;
	info.ulFreePrivateMemory = ~0;

	TEE_MemMove(&info.hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info.firmwareVersion, &fwver, sizeof(hwver));

	// TODO: get time and convert from refence into YYYYMMDDhhmmss/UTC
	TEE_MemFill(info.utcTime, 0, sizeof(info.utcTime));

	/* Return to caller with data */
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return SKS_OK;
}

uint32_t ck_token_mecha_ids(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	// TODO: get the list of supported mechanism
	const uint32_t mecha_list[] = {
		SKS_PROC_AES_ECB_NOPAD,
		SKS_PROC_AES_CBC_NOPAD,
		SKS_PROC_AES_CBC_PAD,
		SKS_PROC_AES_CTS,
		SKS_PROC_AES_CTR,
		SKS_PROC_AES_GCM,
		SKS_PROC_AES_CCM,
	};
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(mecha_list)) {
		out->memref.size = sizeof(mecha_list);
		return SKS_SHORT_BUFFER;
	}

	if (ctrl->memref.size != sizeof(token_id))
		return SKS_BAD_PARAM;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	/* TODO: can a token support a restricted mechanism list */
	out->memref.size = sizeof(mecha_list);
	TEE_MemMove(out->memref.buffer, mecha_list, sizeof(mecha_list));

	return SKS_OK;
}

uint32_t ck_token_mecha_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	struct sks_ck_mecha_info info;
	uint32_t type;
	uint32_t token_id;
	struct ck_token *token;
	char *ctrl_ptr;

	if (!ctrl || in || !out)
		return SKS_BAD_PARAM;

	if (out->memref.size < sizeof(info)) {
		out->memref.size = sizeof(info);
		return SKS_SHORT_BUFFER;
	}

	if (ctrl->memref.size != 2 * sizeof(uint32_t))
		return SKS_BAD_PARAM;

	ctrl_ptr = ctrl->memref.buffer;
	TEE_MemMove(&token_id, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	TEE_MemMove(&type, ctrl_ptr, sizeof(uint32_t));

	token = get_token(token_id);
	if (!token)
		return SKS_INVALID_SLOT;

	TEE_MemFill(&info, 0, sizeof(info));

	/* TODO: full list of supported algorithm/mechanism */
	switch (type) {
	case SKS_PROC_AES_GCM:
	case SKS_PROC_AES_CCM:
		info.flags |= SKS_PROC_SIGN | SKS_PROC_VERIFY;
	case SKS_PROC_AES_ECB_NOPAD:
	case SKS_PROC_AES_CBC_NOPAD:
	case SKS_PROC_AES_CBC_PAD:
	case SKS_PROC_AES_CTS:
	case SKS_PROC_AES_CTR:
		info.flags |= SKS_PROC_ENCRYPT | SKS_PROC_DECRYPT |
			     SKS_PROC_WRAP | SKS_PROC_UNWRAP | SKS_PROC_DERIVE;
		info.min_key_size =  128;
		info.max_key_size =  256;
		break;

	default:
		break;
	}

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return SKS_OK;
}
