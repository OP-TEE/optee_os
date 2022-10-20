// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <crypto/internal_aes-gcm.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <ipi.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

/*
 * This driver does not queue/pad non-aligned data.
 *
 * Allow debug information for future PLM work: if the PLM can not implement
 * the required changes, we might be able to do it in OP-TEE.
 */
#define DEBUG_VERSAL_AES 0

#define GCM_TAG_LEN		16

#define	XSECURE_AES_KEY_SIZE_128  0   /* Key Length = 32 bytes = 256 bits */
#define	XSECURE_AES_KEY_SIZE_256  2   /* Key Length = 16 bytes = 128 bits */

#define XSECURE_ENCRYPT 0
#define XSECURE_DECRYPT 1

enum versal_aes_err {
	AES_GCM_TAG_MISMATCH = 0x40,
	AES_KEY_CLEAR_ERROR,
	AES_DPA_CM_NOT_SUPPORTED,
	AES_KAT_WRITE_KEY_FAILED_ERROR,
	AES_KAT_DECRYPT_INIT_FAILED_ERROR,
	AES_KAT_GCM_TAG_MISMATCH_ERROR,
	AES_KAT_DATA_MISMATCH_ERROR,
	AES_KAT_FAILED_ERROR,
	AESDPACM_KAT_WRITE_KEY_FAILED_ERROR,
	AESDPACM_KAT_KEYLOAD_FAILED_ERROR,
	AESDPACM_SSS_CFG_FAILED_ERROR,
	AESDPACM_KAT_FAILED_ERROR,
	AESDPACM_KAT_CHECK1_FAILED_ERROR,
	AESDPACM_KAT_CHECK2_FAILED_ERROR,
	AESDPACM_KAT_CHECK3_FAILED_ERROR,
	AESDPACM_KAT_CHECK4_FAILED_ERROR,
	AESDPACM_KAT_CHECK5_FAILED_ERROR,
	AES_INVALID_PARAM,
	AESKAT_INVALID_PARAM,
	AES_STATE_MISMATCH_ERROR,
	AES_DEVICE_KEY_NOT_ALLOWED,
};

#define VERSAL_AES_ERROR(m) { . error = (m), .name = TO_STR(m) }

static const char *versal_aes_error(uint8_t err)
{
	const struct {
		enum versal_aes_err error;
		const char *name;
	} elist[] = {
		VERSAL_AES_ERROR(AES_GCM_TAG_MISMATCH),
		VERSAL_AES_ERROR(AES_KEY_CLEAR_ERROR),
		VERSAL_AES_ERROR(AES_DPA_CM_NOT_SUPPORTED),
		VERSAL_AES_ERROR(AES_KAT_WRITE_KEY_FAILED_ERROR),
		VERSAL_AES_ERROR(AES_KAT_DECRYPT_INIT_FAILED_ERROR),
		VERSAL_AES_ERROR(AES_KAT_GCM_TAG_MISMATCH_ERROR),
		VERSAL_AES_ERROR(AES_KAT_DATA_MISMATCH_ERROR),
		VERSAL_AES_ERROR(AES_KAT_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_WRITE_KEY_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_KEYLOAD_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_SSS_CFG_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_CHECK1_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_CHECK2_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_CHECK3_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_CHECK4_FAILED_ERROR),
		VERSAL_AES_ERROR(AESDPACM_KAT_CHECK5_FAILED_ERROR),
		VERSAL_AES_ERROR(AES_INVALID_PARAM),
		VERSAL_AES_ERROR(AESKAT_INVALID_PARAM),
		VERSAL_AES_ERROR(AES_STATE_MISMATCH_ERROR),
		VERSAL_AES_ERROR(AES_DEVICE_KEY_NOT_ALLOWED),
	};

	if (err >= AES_GCM_TAG_MISMATCH && err <= AES_DEVICE_KEY_NOT_ALLOWED) {
		if (elist[err - AES_GCM_TAG_MISMATCH].name)
			return elist[err - AES_GCM_TAG_MISMATCH].name;

		return "Invalid";
	}

	return "Unknown";
}

enum aes_key_src {
	XSECURE_AES_BBRAM_KEY = 0,              /* BBRAM Key */
	XSECURE_AES_BBRAM_RED_KEY,              /* BBRAM Red Key */
	XSECURE_AES_BH_KEY,                     /* BH Key */
	XSECURE_AES_BH_RED_KEY,                 /* BH Red Key */
	XSECURE_AES_EFUSE_KEY,                  /* eFUSE Key */
	XSECURE_AES_EFUSE_RED_KEY,              /* eFUSE Red Key */
	XSECURE_AES_EFUSE_USER_KEY_0,           /* eFUSE User Key 0 */
	XSECURE_AES_EFUSE_USER_KEY_1,           /* eFUSE User Key 1 */
	XSECURE_AES_EFUSE_USER_RED_KEY_0,       /* eFUSE User Red Key 0 */
	XSECURE_AES_EFUSE_USER_RED_KEY_1,       /* eFUSE User Red Key 1 */
	XSECURE_AES_KUP_KEY,                    /* KUP key */
	XSECURE_AES_PUF_KEY,                    /* PUF key */
	XSECURE_AES_USER_KEY_0,                 /* User Key 0 */
	XSECURE_AES_USER_KEY_1,                 /* User Key 1 */
	XSECURE_AES_USER_KEY_2,                 /* User Key 2 */
	XSECURE_AES_USER_KEY_3,                 /* User Key 3 */
	XSECURE_AES_USER_KEY_4,                 /* User Key 4 */
	XSECURE_AES_USER_KEY_5,                 /* User Key 5 */
	XSECURE_AES_USER_KEY_6,                 /* User Key 6 */
	XSECURE_AES_USER_KEY_7,                 /* User Key 7 */
	XSECURE_AES_EXPANDED_KEYS,              /* Expanded keys */
	XSECURE_AES_ALL_KEYS,                   /* AES All keys */
};

struct versal_payload {
	struct versal_mbox_mem input_cmd;
	struct versal_mbox_mem src;
	struct versal_mbox_mem dst;
	bool encrypt;
};

struct versal_aad {
	struct versal_mbox_mem mem;
};

struct versal_node {
	struct versal_payload payload;
	struct versal_aad aad;
	bool is_aad;
	STAILQ_ENTRY(versal_node) link;
};

struct versal_init {
	uint32_t key_len;
	uint32_t operation;
	struct versal_mbox_mem key;
	struct versal_mbox_mem nonce;
	struct versal_mbox_mem init_buf;
};

struct versal_ae_ctx {
	struct crypto_authenc_ctx a_ctx;
};

struct versal_context_node {
	struct versal_ae_ctx *ctx;
	STAILQ_ENTRY(versal_context_node) link;
};

enum engine_state {
	READY = 1, INIT = 2, FINALIZED = 3,
};

static struct mutex engine_lock = MUTEX_INITIALIZER;

static struct versal_engine {
	enum aes_key_src key_src;
	enum engine_state state;
	struct versal_init init;
	struct refcount refc;
	struct mutex *lock; /* protect the HW instance */
	STAILQ_HEAD(authenc_context_list, versal_context_node) context_list;
	STAILQ_HEAD(authenc_replay_list, versal_node) replay_list;
} engine = {
	.key_src = XSECURE_AES_USER_KEY_0,
	.lock = &engine_lock,
};

static struct versal_ae_ctx *to_versal_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct versal_ae_ctx, a_ctx);
}

static TEE_Result replay_init(void)
{
	struct versal_cmd_args arg = { };
	uint32_t err = 0;

	if (versal_crypto_request(VERSAL_AES_INIT, &arg, &err)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	arg.data[arg.dlen++] = engine.init.key_len;
	arg.data[arg.dlen++] = engine.key_src;
	arg.ibuf[0].mem = engine.init.key;

	if (versal_crypto_request(VERSAL_AES_WRITE_KEY, &arg, &err)) {
		EMSG("AES_WRITE_KEY error");
		return TEE_ERROR_GENERIC;
	}

	memset(&arg, 0, sizeof(arg));

	arg.ibuf[0].mem = engine.init.init_buf;
	arg.ibuf[1].mem = engine.init.nonce;
	arg.ibuf[1].only_cache = true;

	if (versal_crypto_request(VERSAL_AES_OP_INIT, &arg, &err)) {
		EMSG("AES_OP_INIT error");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result replay_aad(struct versal_aad *p)
{
	struct versal_cmd_args arg = { };
	uint32_t err = 0;

	arg.data[arg.dlen++] = p->mem.len % 16 ? p->mem.alloc_len : p->mem.len;
	arg.ibuf[0].mem = p->mem;

	if (versal_crypto_request(VERSAL_AES_UPDATE_AAD, &arg, &err)) {
		EMSG("AES_UPDATE_AAD error: %s", versal_aes_error(err));
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result replay_payload(struct versal_payload *p)
{
	enum versal_crypto_api id = VERSAL_AES_DECRYPT_UPDATE;
	struct versal_cmd_args arg = { };
	uint32_t err = 0;

	arg.ibuf[0].mem = p->input_cmd;
	arg.ibuf[1].mem = p->dst;
	arg.ibuf[2].mem = p->src;

	if (p->encrypt)
		id = VERSAL_AES_ENCRYPT_UPDATE;

	if (versal_crypto_request(id, &arg, &err)) {
		EMSG("AES_UPDATE_PAYLOAD error: %s", versal_aes_error(err));
		return  TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result do_replay(void)
{
	struct versal_node *node = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = replay_init();
	if (ret)
		return ret;

	STAILQ_FOREACH(node, &engine.replay_list, link) {
		if (node->is_aad) {
			ret = replay_aad(&node->aad);
			if (ret)
				return ret;
		} else {
			ret = replay_payload(&node->payload);
			if (ret)
				return ret;
		}
	}

	/* Engine has been init */
	engine.state = INIT;

	return TEE_SUCCESS;
}

static bool engine_in_use(void)
{
	if (STAILQ_EMPTY(&engine.context_list))
		return false;

	return true;
}

static bool context_allowed(struct crypto_authenc_ctx *ctx)
{
	struct versal_context_node *node = NULL;

	STAILQ_FOREACH(node, &engine.context_list, link) {
		if (node->ctx == to_versal_ctx(ctx))
			return true;
	}

	return false;
}

static TEE_Result do_init(struct drvcrypt_authenc_init *dinit)
{
	uint32_t key_len = XSECURE_AES_KEY_SIZE_128;
	struct versal_context_node *node = NULL;
	struct versal_aes_init *init = NULL;
	struct versal_mbox_mem init_buf = { };
	struct versal_mbox_mem key = { };
	struct versal_mbox_mem nonce = { };
	struct versal_cmd_args arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	if (engine_in_use()) {
		EMSG("Versal: AES-GCM Engine busy");
		return TEE_ERROR_BUSY;
	}

	if (dinit->key.length != 32 && dinit->key.length != 16)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dinit->key.length == 32)
		key_len = XSECURE_AES_KEY_SIZE_256;

	if (engine.state != READY)
		return TEE_ERROR_BAD_STATE;

	/* Initialize the AES engine */
	if (versal_crypto_request(VERSAL_AES_INIT, &arg, &err)) {
		EMSG("AES_INIT error: %s", versal_aes_error(err));
		return TEE_ERROR_GENERIC;
	}

	/* Write the key */
	versal_mbox_alloc(dinit->key.length, dinit->key.data, &key);

	arg.data[arg.dlen++] = key_len;
	arg.data[arg.dlen++] = engine.key_src;
	arg.ibuf[0].mem = key;

	if (versal_crypto_request(VERSAL_AES_WRITE_KEY, &arg, &err)) {
		EMSG("AES_WRITE_KEY error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto error;
	}

	memset(&arg, 0, sizeof(arg));

	/* Send the initialization structure */
	versal_mbox_alloc(sizeof(*init), NULL, &init_buf);
	versal_mbox_alloc(dinit->nonce.length, dinit->nonce.data, &nonce);

	init = init_buf.buf;
	init->iv_addr = virt_to_phys(nonce.buf);
	init->operation = dinit->encrypt ? XSECURE_ENCRYPT : XSECURE_DECRYPT;
	init->key_src = engine.key_src;
	init->key_len = key_len;

	arg.ibuf[0].mem = init_buf;
	arg.ibuf[1].mem = nonce;
	arg.ibuf[1].only_cache = true;

	if (versal_crypto_request(VERSAL_AES_OP_INIT, &arg, &err)) {
		EMSG("AES_OP_INIT error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto error;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	/* Save key context */
	engine.init.operation = dinit->encrypt ?
				XSECURE_ENCRYPT : XSECURE_DECRYPT;
	engine.init.key_len = key_len;
	engine.init.init_buf = init_buf;
	engine.init.nonce = nonce;
	engine.init.key = key;

	/* Active context */
	node->ctx = to_versal_ctx(dinit->ctx);
	STAILQ_INSERT_TAIL(&engine.context_list, node, link);

	/* Engine has been init*/
	engine.state = INIT;

	return TEE_SUCCESS;
error:
	free(key.buf);
	free(init_buf.buf);
	free(nonce.buf);

	return ret;
}

static TEE_Result do_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct versal_node *node = NULL;
	uint32_t err = 0;

	/* This context has not been inited */
	if (!context_allowed(dupdate->ctx))
		return TEE_ERROR_BUSY;

	/* There is a copy of the context: don't allow updates, only finalize */
	if (refcount_val(&engine.refc) > 1)
		return TEE_ERROR_BUSY;

	/* There was a copy of the context and it was finalized, then replay */
	if (engine.state == FINALIZED)
		do_replay();

	versal_mbox_alloc(dupdate->aad.length, dupdate->aad.data, &p);

	arg.data[arg.dlen++] = p.len % 16 ? p.alloc_len : p.len;
	arg.ibuf[0].mem = p;

#if DEBUG_VERSAL_AES
	IMSG("versal: aad length - requested: %zu, sent to plm: %"PRIu32,
	     dupdate->aad.length, arg.data[0]);
#endif
	if (versal_crypto_request(VERSAL_AES_UPDATE_AAD, &arg, &err)) {
		EMSG("AES_UPDATE_AAD error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto error;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto error;
	}

	/* Save the context */
	node->aad.mem = p;
	node->is_aad = true;
	STAILQ_INSERT_TAIL(&engine.replay_list, node, link);

	return TEE_SUCCESS;
error:
	free(p.buf);
	return ret;
}

static TEE_Result
update_payload(struct drvcrypt_authenc_update_payload *dupdate, bool is_last)
{
	enum versal_crypto_api id = VERSAL_AES_DECRYPT_UPDATE;
	struct versal_aes_input_param *input = NULL;
	struct versal_mbox_mem input_cmd = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem q = { };
	TEE_Result ret = TEE_SUCCESS;
	struct versal_cmd_args arg = { };
	struct versal_node *node = NULL;
	uint32_t err = 0;

	if (!context_allowed(dupdate->ctx))
		return TEE_ERROR_BUSY;

	if (!dupdate->src.length || dupdate->src.length % 4) {
		EMSG("Versal AES payload length not word aligned (len = %zu)",
		     dupdate->src.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	versal_mbox_alloc(dupdate->src.length, dupdate->src.data, &p);
	versal_mbox_alloc(dupdate->dst.length, NULL, &q);
	versal_mbox_alloc(sizeof(*input), NULL, &input_cmd);

	input = input_cmd.buf;
	input->input_addr = virt_to_phys(p.buf);
	input->input_len = p.len % 16 ? p.alloc_len : p.len;
	input->is_last = is_last;

	arg.ibuf[0].mem = input_cmd;
	arg.ibuf[1].mem = q;
	arg.ibuf[2].mem = p;

	if (dupdate->encrypt)
		id = VERSAL_AES_ENCRYPT_UPDATE;

#if DEBUG_VERSAL_AES
	IMSG("versal: payload length - requested %zu, sent to plm: %"PRIu32,
	     dupdate->src.length, input->input_len);
	IMSG("versal: destination length - %zu ", dupdate->dst.length);
#endif
	if (versal_crypto_request(id, &arg, &err)) {
		EMSG("AES_UPDATE_PAYLOAD error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	if (dupdate->dst.data)
		memcpy(dupdate->dst.data, q.buf, dupdate->dst.length);

	if (!is_last) {
		node = calloc(1, sizeof(*node));
		if (!node) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		node->is_aad = false;
		node->payload.dst = q;
		node->payload.src = p;
		node->payload.input_cmd = input_cmd;
		node->payload.encrypt = dupdate->encrypt;
		STAILQ_INSERT_TAIL(&engine.replay_list, node, link);

		return TEE_SUCCESS;
	}
out:
	free(p.buf);
	free(q.buf);
	free(input_cmd.buf);

	return ret;
}

static TEE_Result do_update_payload(struct drvcrypt_authenc_update_payload *p)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!context_allowed(p->ctx))
		return TEE_ERROR_BUSY;

	/*
	 * If there is a copy, we don't allow updates until one of the copies
	 * has been deleted
	 */
	if (refcount_val(&engine.refc) > 1)
		return TEE_ERROR_BUSY;

	/*
	 * If there was a copy and it was finalized, we need to replay before
	 * we can update; do not clear the list so the state can be copied
	 */
	if (engine.state == FINALIZED) {
		ret = do_replay();
		if (ret)
			return ret;
	}

	return update_payload(p, false);
}

static TEE_Result do_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	if (!context_allowed(dfinal->ctx))
		return TEE_ERROR_BUSY;

	if (engine.state == FINALIZED) {
		DMSG("Operation was already finalized");
		ret = do_replay();
		if (ret)
			return ret;
	}

	if (engine.state != INIT)
		panic();

	last.ctx = dfinal->ctx;
	last.dst = dfinal->dst;
	last.encrypt = true;
	last.src = dfinal->src;

	ret = update_payload(&last, true);
	if (ret)
		return ret;

	memcpy(dfinal->dst.data, last.dst.data, dfinal->dst.length);

	versal_mbox_alloc(GCM_TAG_LEN, NULL, &p);

	arg.ibuf[0].mem = p;
	if (versal_crypto_request(VERSAL_AES_ENCRYPT_FINAL, &arg, &err)) {
		EMSG("AES_ENCRYPT_FINAL error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dfinal->tag.data, p.buf, GCM_TAG_LEN);
	dfinal->tag.length = GCM_TAG_LEN;
out:
	free(p.buf);

	if (refcount_val(&engine.refc) > 1)
		engine.state = FINALIZED;
	else
		engine.state = READY;

	return ret;
}

static TEE_Result do_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;

	if (!context_allowed(dfinal->ctx))
		return TEE_ERROR_BUSY;

	if (engine.state == FINALIZED) {
		DMSG("Operation was already finalized");
		ret = do_replay();
		if (ret)
			return ret;
	}

	if (engine.state != INIT)
		panic();

	last.encrypt = false;
	last.ctx = dfinal->ctx;
	last.dst = dfinal->dst;
	last.src = dfinal->src;

	ret = update_payload(&last, true);
	if (ret)
		return ret;

	versal_mbox_alloc(dfinal->tag.length, dfinal->tag.data, &p);
	arg.ibuf[0].mem = p;

	if (versal_crypto_request(VERSAL_AES_DECRYPT_FINAL, &arg, &err)) {
		EMSG("AES_DECRYPT_FINAL error: %s", versal_aes_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dfinal->dst.data, last.dst.data, dfinal->dst.length);
	memcpy(dfinal->tag.data, p.buf, GCM_TAG_LEN);
	dfinal->tag.length = GCM_TAG_LEN;
out:
	free(p.buf);

	if (refcount_val(&engine.refc) > 1)
		engine.state = FINALIZED;
	else
		engine.state = READY;

	return ret;
}

static void do_final(void *ctx __unused)
{
}

static void do_free(void *ctx)
{
	struct versal_ae_ctx *c = to_versal_ctx(ctx);
	struct versal_node *next = NULL;
	struct versal_node *node = NULL;
	struct versal_context_node *ctx_next = NULL;
	struct versal_context_node *ctx_node = NULL;
	bool release = false;

	if (refcount_dec(&engine.refc)) {
		/* this is a final release */
		release = true;
		refcount_set(&engine.refc, 1);
		engine.state = READY;
		free(engine.init.init_buf.buf);
		free(engine.init.nonce.buf);
		free(engine.init.key.buf);
		memset(&engine.init, 0, sizeof(engine.init));
		STAILQ_FOREACH_SAFE(node, &engine.replay_list, link, next) {
			STAILQ_REMOVE(&engine.replay_list, node,
				      versal_node, link);
			if (node->is_aad) {
				free(node->aad.mem.buf);
			} else {
				free(node->payload.dst.buf);
				free(node->payload.src.buf);
				free(node->payload.input_cmd.buf);
			}
			free(node);
		}
	}

	STAILQ_FOREACH_SAFE(ctx_node, &engine.context_list, link, ctx_next) {
		if (c == ctx_node->ctx) {
			STAILQ_REMOVE(&engine.context_list, ctx_node,
				      versal_context_node, link);
			free(ctx_node);
		}
	}

	if (release && engine_in_use())
		panic();

	free(c);
}

static void do_copy_state(void *dst_ctx, void *src_ctx)
{
	struct versal_context_node *node = NULL;

	STAILQ_FOREACH(node, &engine.context_list, link) {
		if (node->ctx != to_versal_ctx(src_ctx))
			continue;
		/*
		 * The running context has been copied: from now on we can only
		 * finalize any of the contexts until there is only one active
		 * again.
		 */
		node = calloc(1, sizeof(*node));
		if (!node)
			panic();

		node->ctx = to_versal_ctx(dst_ctx);
		STAILQ_INSERT_TAIL(&engine.context_list, node, link);

		/* number of active contexts */
		refcount_inc(&engine.refc);

		return;
	}

	panic();
}

static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	struct versal_ae_ctx *c = NULL;

	if (algo != TEE_ALG_AES_GCM)
		return TEE_ERROR_NOT_IMPLEMENTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx = &c->a_ctx;

	return TEE_SUCCESS;
}

static TEE_Result
do_update_payload_locked(struct drvcrypt_authenc_update_payload *p)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(engine.lock);
	ret = do_update_payload(p);
	mutex_unlock(engine.lock);
	return ret;
}

static TEE_Result
do_update_aad_locked(struct drvcrypt_authenc_update_aad *p)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(engine.lock);
	ret = do_update_aad(p);
	mutex_unlock(engine.lock);
	return ret;
}

static void do_copy_state_locked(void *dst, void *src)
{
	mutex_lock(engine.lock);
	do_copy_state(dst, src);
	mutex_unlock(engine.lock);
}

static TEE_Result do_enc_final_locked(struct drvcrypt_authenc_final *p)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(engine.lock);
	ret = do_enc_final(p);
	mutex_unlock(engine.lock);
	return ret;
}

static TEE_Result do_dec_final_locked(struct drvcrypt_authenc_final *p)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(engine.lock);
	ret = do_dec_final(p);
	mutex_unlock(engine.lock);
	return ret;
}

static void do_free_locked(void *p)
{
	mutex_lock(engine.lock);
	do_free(p);
	mutex_unlock(engine.lock);
}

static TEE_Result do_init_locked(struct drvcrypt_authenc_init *p)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(engine.lock);
	ret = do_init(p);
	mutex_unlock(engine.lock);
	return ret;
}

static struct drvcrypt_authenc versal_authenc = {
	.update_payload = do_update_payload_locked,
	.update_aad = do_update_aad_locked,
	.copy_state = do_copy_state_locked,
	.enc_final = do_enc_final_locked,
	.dec_final = do_dec_final_locked,
	.free_ctx = do_free_locked,
	.alloc_ctx = do_allocate,
	.init = do_init_locked,
	.final = do_final,
};

static TEE_Result enable_secure_status(void)
{
	/* Once Linux has support, we need to reserve the device */
	return TEE_SUCCESS;
}

static TEE_Result versal_register_authenc(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_authenc(&versal_authenc);
	if (ret)
		return ret;

	if (engine.key_src < XSECURE_AES_USER_KEY_0 ||
	    engine.key_src > XSECURE_AES_USER_KEY_7)
		return TEE_ERROR_GENERIC;

	engine.state = READY;
	STAILQ_INIT(&engine.replay_list);
	STAILQ_INIT(&engine.context_list);
	refcount_set(&engine.refc, 1);

	return enable_secure_status();
}

driver_init_late(versal_register_authenc);
