// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/embedded_ts.h>
#include <kernel/ldelf_loader.h>
#include <kernel/secure_partition.h>
#include <kernel/thread_spmc.h>
#include <kernel/ts_store.h>
#include <ldelf.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/vm.h>
#include <optee_ffa.h>
#include <stdio.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>
#include <zlib.h>

static const struct ts_ops *_sp_ops;

/* List that holds all of the loaded SP's */
static struct sp_sessions_head open_sp_sessions =
	TAILQ_HEAD_INITIALIZER(open_sp_sessions);

static const struct ts_ops sp_ops __rodata_unpaged = {
};

static const struct embedded_ts *find_secure_partition(const TEE_UUID *uuid)
{
	const struct embedded_ts *sp = NULL;

	for_each_secure_partition(sp) {
		if (!memcmp(&sp->uuid, uuid, sizeof(*uuid)))
			return sp;
	}
	return NULL;
}

bool is_sp_ctx(struct ts_ctx *ctx)
{
	return ctx && (ctx->ops == _sp_ops);
}

static void set_sp_ctx_ops(struct ts_ctx *ctx)
{
	ctx->ops = _sp_ops;
}

struct sp_session *sp_get_session(uint32_t session_id)
{
	struct sp_session *s = NULL;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (s->endpoint_id == session_id)
			return s;
	}

	return NULL;
}

static void sp_init_info(struct sp_ctx *ctx)
{
	struct sp_ffa_init_info *info = NULL;

	ctx->uctx.stack_ptr -= ROUNDUP(sizeof(*info), STACK_ALIGNMENT);

	ctx->sp_regs.x[0]  = (uintptr_t)ctx->uctx.stack_ptr;
	info = (struct sp_ffa_init_info *)ctx->uctx.stack_ptr;

	info->magic = 0;
	info->count = 0;
}

static uint16_t new_session_id(struct sp_sessions_head *open_sessions)
{
	struct sp_session *last = NULL;
	uint16_t id = SPMC_ENDPOINT_ID + 1;

	last = TAILQ_LAST(open_sessions, sp_sessions_head);
	if (last)
		id = last->endpoint_id + 1;

	assert(id > SPMC_ENDPOINT_ID);
	return id;
}

static TEE_Result sp_create_ctx(const TEE_UUID *uuid, struct sp_session *s)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_ctx *spc = NULL;

	/* Register context */
	spc = calloc(1, sizeof(struct sp_ctx));
	if (!spc)
		return TEE_ERROR_OUT_OF_MEMORY;

	spc->uctx.ts_ctx = &spc->ts_ctx;
	spc->open_session = s;
	s->ts_sess.ctx = &spc->ts_ctx;
	spc->ts_ctx.uuid = *uuid;

	res = vm_info_init(&spc->uctx);
	if (res)
		goto err;

	set_sp_ctx_ops(&spc->ts_ctx);

	return TEE_SUCCESS;

err:
	free(spc);
	return res;
}

static TEE_Result sp_create_session(struct sp_sessions_head *open_sessions,
				    const TEE_UUID *uuid,
				    struct sp_session **sess)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = calloc(1, sizeof(struct sp_session));

	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->endpoint_id = new_session_id(open_sessions);
	if (!s->endpoint_id) {
		res = TEE_ERROR_OVERFLOW;
		goto err;
	}

	DMSG("Loading Secure Partition %pUl", (void *)uuid);
	res = sp_create_ctx(uuid, s);
	if (res)
		goto err;

	TAILQ_INSERT_TAIL(open_sessions, s, link);
	*sess = s;
	return TEE_SUCCESS;

err:
	free(s);
	return res;
}

static TEE_Result sp_init_set_registers(struct sp_ctx *ctx)
{
	struct thread_ctx_regs *sp_regs = &ctx->sp_regs;
	uint64_t x0 = sp_regs->x[0];

	/* Clear all addresses except x0, x0 contains the info address. */
	memset(sp_regs, 0, sizeof(*sp_regs));
	sp_regs->sp = ctx->uctx.stack_ptr;
	sp_regs->x[0] = x0;
	sp_regs->pc = ctx->uctx.entry_func;

	return TEE_SUCCESS;
}

static TEE_Result sp_open_session(struct sp_session **sess,
				  struct sp_sessions_head *open_sessions,
				  const TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = NULL;
	struct sp_ctx *ctx = NULL;

	if (!find_secure_partition(uuid))
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = sp_create_session(open_sessions, uuid, &s);
	if (res != TEE_SUCCESS) {
		DMSG("sp_create_session failed %#"PRIx32, res);
		return res;
	}

	ctx = to_sp_ctx(s->ts_sess.ctx);
	assert(ctx);
	if (!ctx)
		return TEE_ERROR_TARGET_DEAD;
	*sess = s;

	ts_push_current_session(&s->ts_sess);
	/* Load the SP using ldelf. */
	ldelf_load_ldelf(&ctx->uctx);
	res = ldelf_init_with_ldelf(&s->ts_sess, &ctx->uctx);

	if (res != TEE_SUCCESS) {
		EMSG("Failed. loading SP using ldelf %#"PRIx32, res);
		ts_pop_current_session();
		return TEE_ERROR_TARGET_DEAD;
	}

	/* Make the SP ready for its first run */
	s->state = sp_idle;
	s->caller_id = 0;
	sp_init_info(ctx);
	sp_init_set_registers(ctx);
	ts_pop_current_session();

	return TEE_SUCCESS;
}

static TEE_Result sp_init_uuid(const TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *sess = NULL;

	res = sp_open_session(&sess,
			      &open_sp_sessions,
			      uuid);
	if (res)
		return res;

	return res;
}

static TEE_Result sp_init_all(void)
{
	TEE_Result res = TEE_SUCCESS;
	const struct embedded_ts *sp = NULL;
	char __maybe_unused msg[60] = { '\0', };

	_sp_ops = &sp_ops;

	for_each_secure_partition(sp) {
		if (sp->uncompressed_size)
			snprintf(msg, sizeof(msg),
				 " (compressed, uncompressed %u)",
				 sp->uncompressed_size);
		else
			msg[0] = '\0';
		DMSG("SP %pUl size %u%s", (void *)&sp->uuid, sp->size, msg);

		res = sp_init_uuid(&sp->uuid);

		if (res != TEE_SUCCESS) {
			EMSG("Failed initializing SP(%pUl) err:%#"PRIx32,
			     &sp->uuid, res);
			if (!IS_ENABLED(CFG_SP_SKIP_FAILED))
				panic();
		}
	}

	return TEE_SUCCESS;
}

boot_final(sp_init_all);

static TEE_Result secure_partition_open(const TEE_UUID *uuid,
					struct ts_store_handle **h)
{
	return emb_ts_open(uuid, h, find_secure_partition);
}

REGISTER_SP_STORE(2) = {
	.description = "SP store",
	.open = secure_partition_open,
	.get_size = emb_ts_get_size,
	.get_tag = emb_ts_get_tag,
	.read = emb_ts_read,
	.close = emb_ts_close,
};
