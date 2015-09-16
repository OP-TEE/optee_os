/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <types_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <arm.h>
#include <tee_api_types.h>
#include <user_ta_header.h>
#include <util.h>
#include <kernel/tee_compat.h>
#include <tee/tee_svc.h>
#include <tee/arch_svc.h>
#include <tee/abi.h>
#include <mm/tee_mmu.h>
#include <kernel/tee_misc.h>
#include <kernel/panic.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_cryp_provider.h>
#include <tee/tee_cryp_utl.h>
#include <kernel/tee_common.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_ta_static.h>
#include <mm/tee_mm.h>
#include <trace.h>
#include <kernel/tee_rpc.h>
#include <kernel/tee_rpc_types.h>
#include <kernel/mutex.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_storage.h>
#include <kernel/tee_time.h>
#include <sm/tee_mon.h>
#include <user_ta_header.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <kernel/thread.h>
#include <sm/teesmc.h>
#include <kernel/tee_misc.h>
#include <ta_pub_key.h>
#include <kernel/tee_kta_trace.h>
#include <kernel/trace_ta.h>
#include <signed_hdr.h>
#include <utee_defines.h>
#include "elf_load.h"

/*
 * Use this invalid ID for a static TA, since
 * session is not needed for calling static TA.
 */
#define TEE_SESSION_ID_STATIC_TA 0xFFFFFFFF

#define TEE_TA_STACK_ALIGNMENT   8

enum tee_user_ta_func {
	USER_TA_FUNC_OPEN_CLIENT_SESSION = 0,
	USER_TA_FUNC_CLOSE_CLIENT_SESSION,
	USER_TA_FUNC_INVOKE_COMMAND
};

typedef enum {
	COMMAND_INVOKE_COMMAND = 0,
	COMMAND_OPEN_SESSION,
	COMMAND_CREATE_ENTRY_POINT,
	COMMAND_CLOSE_SESSION,
	COMMAND_DESTROY_ENTRY_POINT,
} command_t;

struct param_ta {
	struct tee_ta_session *sess;
	uint32_t cmd;
	struct tee_ta_param *param;
	TEE_Result res;
};

/* This mutex protects the critical section in tee_ta_init_session */
static struct mutex tee_ta_mutex = MUTEX_INITIALIZER;
static struct condvar tee_ta_cv = CONDVAR_INITIALIZER;
static int tee_ta_single_instance_thread = THREAD_ID_INVALID;
static size_t tee_ta_single_instance_count;

static TEE_Result tee_ta_rpc_free(uint32_t handle);

/*
 * Get/Set resisdent session, to leave/re-enter session execution context.
 */
static struct tee_ta_session *get_tee_rs(void)
{
	return thread_get_tsd();
}

static void set_tee_rs(struct tee_ta_session *tee_rs)
{
	thread_set_tsd(tee_rs);
}

static void lock_single_instance(void)
{
	/* Requires tee_ta_mutex to be held */
	if (tee_ta_single_instance_thread != thread_get_id()) {
		/* Wait until the single-instance lock is available. */
		while (tee_ta_single_instance_thread != THREAD_ID_INVALID)
			condvar_wait(&tee_ta_cv, &tee_ta_mutex);

		tee_ta_single_instance_thread = thread_get_id();
		assert(tee_ta_single_instance_count == 0);
	}

	tee_ta_single_instance_count++;
}

static void unlock_single_instance(void)
{
	/* Requires tee_ta_mutex to be held */
	assert(tee_ta_single_instance_thread == thread_get_id());
	assert(tee_ta_single_instance_count > 0);

	tee_ta_single_instance_count--;
	if (tee_ta_single_instance_count == 0) {
		tee_ta_single_instance_thread = THREAD_ID_INVALID;
		condvar_signal(&tee_ta_cv);
	}
}

static bool has_single_instance_lock(void)
{
	/* Requires tee_ta_mutex to be held */
	return tee_ta_single_instance_thread == thread_get_id();
}

static bool tee_ta_try_set_busy(struct tee_ta_ctx *ctx)
{
	bool rc = true;

	mutex_lock(&tee_ta_mutex);

	if (ctx->flags & TA_FLAG_SINGLE_INSTANCE)
		lock_single_instance();

	if (has_single_instance_lock()) {
		if (ctx->busy) {
			/*
			 * We're holding the single-instance lock and the
			 * TA is busy, as waiting now would only cause a
			 * dead-lock, we release the lock and return false.
			 */
			rc = false;
			if (ctx->flags & TA_FLAG_SINGLE_INSTANCE)
				unlock_single_instance();
		}
	} else {
		/*
		 * We're not holding the single-instance lock, we're free to
		 * wait for the TA to become available.
		 */
		while (ctx->busy)
			condvar_wait(&ctx->busy_cv, &tee_ta_mutex);
	}

	/* Either it's already true or we should set it to true */
	ctx->busy = true;

	mutex_unlock(&tee_ta_mutex);
	return rc;
}

static void tee_ta_set_busy(struct tee_ta_ctx *ctx)
{
	if (!tee_ta_try_set_busy(ctx))
		panic();
}

static void tee_ta_clear_busy(struct tee_ta_ctx *ctx)
{
	mutex_lock(&tee_ta_mutex);

	assert(ctx->busy);
	ctx->busy = false;
	condvar_signal(&ctx->busy_cv);

	if (ctx->flags & TA_FLAG_SINGLE_INSTANCE)
		unlock_single_instance();

	mutex_unlock(&tee_ta_mutex);
}

/*
 * Jumpers for the static TAs.
 */
static void jumper_invokecommand(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->invoke_command_entry_point(
			(void *)args->sess->user_ctx,
			(uint32_t)args->cmd,
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params);
	OUTMSG("%x", args->res);
}

static void jumper_opensession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->open_session_entry_point(
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params,
			(void **)&args->sess->user_ctx);
	OUTMSG("%x", args->res);
}

static void jumper_createentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->sess->ctx->static_ta->create_entry_point();
	OUTMSG("%x", args->res);
}

static void jumper_closesession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->sess->ctx->static_ta->close_session_entry_point(
			(void *)args->sess->user_ctx);
	args->res = TEE_SUCCESS;
	OUTMSG("%x", args->res);
}

static void jumper_destroyentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->sess->ctx->static_ta->destroy_entry_point();
	args->res = TEE_SUCCESS;
	OUTMSG("%x", args->res);
}

/* Stack size is updated to take into account */
/* the size of the needs of the tee internal libs */

static TEE_Result invoke_ta(struct tee_ta_session *sess, uint32_t cmd,
			    struct tee_ta_param *param, command_t commandtype)
{
	struct param_ta ptas;

	ptas.sess = sess;
	ptas.cmd = cmd;
	ptas.param = param;
	ptas.res = TEE_ERROR_TARGET_DEAD;

	set_tee_rs(sess);

	switch (commandtype) {
	case COMMAND_INVOKE_COMMAND:
		jumper_invokecommand(&ptas);
		break;
	case COMMAND_OPEN_SESSION:
		jumper_opensession(&ptas);
		break;
	case COMMAND_CREATE_ENTRY_POINT:
		jumper_createentrypoint(&ptas);
		break;
	case COMMAND_CLOSE_SESSION:
		jumper_closesession(&ptas);
		break;
	case COMMAND_DESTROY_ENTRY_POINT:
		jumper_destroyentrypoint(&ptas);
		break;
	default:
		EMSG("Do not know how to run the command %d", commandtype);
		ptas.res = TEE_ERROR_GENERIC;
		break;
	}

	set_tee_rs(NULL);

	OUTRMSG(ptas.res);
	return ptas.res;
}

/* set trace level for all installed TAs (TA generic code) */
int tee_ta_set_trace_level(int level)
{
	struct tee_ta_ctx *ctx;

	if ((level > TRACE_MAX) && (level < TRACE_MIN))
		return -1;

	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (ctx->static_ta)
			ctx->static_ta->prop_tracelevel = level;

		/* non-static TA should be done too */
	}
	return 0;
}

/*
 * tee_ta_context_find - Find TA in session list based on a UUID (input)
 * Returns a pointer to the session
 */
static struct tee_ta_ctx *tee_ta_context_find(const TEE_UUID *uuid)
{
	struct tee_ta_ctx *ctx;

	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (memcmp(&ctx->uuid, uuid, sizeof(TEE_UUID)) == 0)
			return ctx;
	}

	return NULL;
}

static TEE_Result tee_ta_load_header(const struct shdr *signed_ta,
		struct shdr **sec_shdr)
{
	size_t s;

	if (!tee_vbuf_is_non_sec(signed_ta, sizeof(*signed_ta)))
		return TEE_ERROR_SECURITY;

	s = SHDR_GET_SIZE(signed_ta);
	if (!tee_vbuf_is_non_sec(signed_ta, s))
		return TEE_ERROR_SECURITY;

	/* Copy signed header into secure memory */
	*sec_shdr = malloc(s);
	if (!*sec_shdr)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(*sec_shdr, signed_ta, s);

	return TEE_SUCCESS;
}

static TEE_Result tee_ta_load_check_shdr(struct shdr *shdr)
{
	struct rsa_public_key key;
	TEE_Result res;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);
	size_t hash_size;

	if (shdr->magic != SHDR_MAGIC || shdr->img_type != SHDR_TA)
		return TEE_ERROR_SECURITY;

	if (TEE_ALG_GET_MAIN_ALG(shdr->algo) != TEE_MAIN_ALGO_RSA)
		return TEE_ERROR_SECURITY;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(shdr->algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		return res;
	if (hash_size != shdr->hash_size)
		return TEE_ERROR_SECURITY;

	if (!crypto_ops.acipher.alloc_rsa_public_key ||
	    !crypto_ops.acipher.rsassa_verify ||
	    !crypto_ops.bignum.bin2bn || !crypto_ops.bignum.free)
		return TEE_ERROR_NOT_SUPPORTED;

	res = crypto_ops.acipher.alloc_rsa_public_key(&key, shdr->sig_size);
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.bignum.bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.bignum.bin2bn(ta_pub_key_modulus,
				       ta_pub_key_modulus_size, key.n);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_ops.acipher.rsassa_verify(shdr->algo, &key, -1,
				SHDR_GET_HASH(shdr), shdr->hash_size,
				SHDR_GET_SIG(shdr), shdr->sig_size);
out:
	crypto_ops.bignum.free(key.n);
	crypto_ops.bignum.free(key.e);
	return res;
}

static TEE_Result tee_ta_load_elf(struct tee_ta_ctx *ctx, struct shdr *shdr,
			const struct shdr *nmem_shdr)
{
	TEE_Result res;
	struct tee_ta_param param = { 0 };
	size_t hash_ctx_size;
	void *hash_ctx = NULL;
	uint32_t hash_algo;
	uint8_t *nwdata = (uint8_t *)nmem_shdr + SHDR_GET_SIZE(shdr);
	size_t nwdata_len = shdr->img_size;
	void *digest = NULL;
	struct elf_load_state *elf_state = NULL;
	struct ta_head *ta_head;
	void *p;
	size_t vasize;

	if (!crypto_ops.hash.get_ctx_size || !crypto_ops.hash.init ||
	    !crypto_ops.hash.update || !crypto_ops.hash.final) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out;
	}
	hash_algo = TEE_DIGEST_HASH_TO_ALGO(shdr->algo);
	res = crypto_ops.hash.get_ctx_size(hash_algo, &hash_ctx_size);
	if (res != TEE_SUCCESS)
		goto out;
	hash_ctx = malloc(hash_ctx_size);
	if (!hash_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = crypto_ops.hash.init(hash_ctx, hash_algo);
	if (res != TEE_SUCCESS)
		goto out;
	res = crypto_ops.hash.update(hash_ctx, hash_algo,
				     (uint8_t *)shdr, sizeof(struct shdr));
	if (res != TEE_SUCCESS)
		goto out;

	res = elf_load_init(hash_ctx, hash_algo, nwdata, nwdata_len,
			    &elf_state);
	if (res != TEE_SUCCESS)
		goto out;

	res = elf_load_head(elf_state, sizeof(struct ta_head), &p, &vasize);
	if (res != TEE_SUCCESS)
		goto out;
	ta_head = p;

	ctx->mm = tee_mm_alloc(&tee_mm_sec_ddr, vasize);
	if (!ctx->mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Currently all TA must execute from DDR */
	if (!(ta_head->flags & TA_FLAG_EXEC_DDR)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	/* Temporary assignment to setup memory mapping */
	ctx->flags = TA_FLAG_EXEC_DDR;

	/* Ensure proper aligment of stack */
	ctx->stack_size = ROUNDUP(ta_head->stack_size,
				  TEE_TA_STACK_ALIGNMENT);

	ctx->mm_stack = tee_mm_alloc(&tee_mm_sec_ddr, ctx->stack_size);
	if (!ctx->mm_stack) {
		EMSG("Failed to allocate %zu bytes for user stack",
		     ctx->stack_size);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Map physical memory into TA virtual memory
	 */

	res = tee_mmu_init(ctx);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_mmu_map(ctx, &param);
	if (res != TEE_SUCCESS)
		goto out;

	tee_mmu_set_ctx(ctx);

	res = elf_load_body(elf_state, tee_mmu_get_load_addr(ctx));
	if (res != TEE_SUCCESS)
		goto out;

	digest = malloc(shdr->hash_size);
	if (!digest) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = crypto_ops.hash.final(hash_ctx, hash_algo, digest,
				    shdr->hash_size);
	if (res != TEE_SUCCESS)
		goto out;

	if (memcmp(digest, SHDR_GET_HASH(shdr), shdr->hash_size) != 0)
		res = TEE_ERROR_SECURITY;

	cache_maintenance_l1(DCACHE_AREA_CLEAN,
			     (void *)tee_mmu_get_load_addr(ctx), vasize);
	cache_maintenance_l1(ICACHE_AREA_INVALIDATE,
			     (void *)tee_mmu_get_load_addr(ctx), vasize);
out:
	elf_load_final(elf_state);
	free(digest);
	free(hash_ctx);
	return res;
}



/*-----------------------------------------------------------------------------
 * Loads TA header and hashes.
 * Verifies the TA signature.
 * Returns session ptr and TEE_Result.
 *---------------------------------------------------------------------------*/
static TEE_Result tee_ta_load(const TEE_UUID *uuid,
			const struct shdr *signed_ta,
			struct tee_ta_ctx **ta_ctx)
{
	TEE_Result res;
	/* man_flags: mandatory flags */
	uint32_t man_flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;
	/* opt_flags: optional flags */
	uint32_t opt_flags = man_flags | TA_FLAG_SINGLE_INSTANCE |
	    TA_FLAG_MULTI_SESSION | TA_FLAG_UNSAFE_NW_PARAMS;
	struct tee_ta_ctx *ctx = NULL;
	struct shdr *sec_shdr = NULL;
	struct ta_head *ta_head;

	res = tee_ta_load_header(signed_ta, &sec_shdr);
	if (res != TEE_SUCCESS)
		goto error_return;

	res = tee_ta_load_check_shdr(sec_shdr);
	if (res != TEE_SUCCESS)
		goto error_return;

	/*
	 * ------------------------------------------------------------------
	 * 2nd step: Register context
	 * Alloc and init the ta context structure, alloc physvical/virtual
	 * memories to store/map the TA.
	 * ------------------------------------------------------------------
	 */

	/*
	 * Register context
	 */

	/* code below must be protected by mutex (multi-threaded) */
	ctx = calloc(1, sizeof(struct tee_ta_ctx));
	if (ctx == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}
	TAILQ_INIT(&ctx->open_sessions);
	TAILQ_INIT(&ctx->cryp_states);
	TAILQ_INIT(&ctx->objects);
	TAILQ_INIT(&ctx->storage_enums);
#if defined(CFG_SE_API)
	ctx->se_service = NULL;
#endif

	res = tee_ta_load_elf(ctx, sec_shdr, signed_ta);
	if (res != TEE_SUCCESS)
		goto error_return;

	ctx->load_addr = tee_mmu_get_load_addr(ctx);
	ta_head = (struct ta_head *)(vaddr_t)ctx->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto error_return;
	}

	/* check input flags bitmask consistency and save flags */
	if ((ta_head->flags & opt_flags) != ta_head->flags ||
	    (ta_head->flags & man_flags) != man_flags) {
		EMSG("TA flag issue: flags=%x opt=%X man=%X",
		     ta_head->flags, opt_flags, man_flags);
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	ctx->flags = ta_head->flags;
	ctx->uuid = ta_head->uuid;
	ctx->open_session_func = ta_head->open_session;
	ctx->close_session_func = ta_head->close_session;
	ctx->invoke_command_func = ta_head->invoke_command;

	ctx->ref_count = 1;

	condvar_init(&ctx->busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, ctx, link);
	*ta_ctx = ctx;

	DMSG("Loaded TA at 0x%" PRIxPTR, tee_mm_get_smem(ctx->mm));
	DMSG("ELF load address 0x%x", ctx->load_addr);

	set_tee_rs(NULL);
	tee_mmu_set_ctx(NULL);
	/* end thread protection (multi-threaded) */

	free(sec_shdr);
	return TEE_SUCCESS;

error_return:
	free(sec_shdr);
	set_tee_rs(NULL);
	tee_mmu_set_ctx(NULL);
	if (ctx != NULL) {
		tee_mmu_final(ctx);
		tee_mm_free(ctx->mm_stack);
		tee_mm_free(ctx->mm);
		free(ctx);
	}
	return res;
}

/* Maps kernal TA params */
static TEE_Result tee_ta_param_pa2va(struct tee_ta_session *sess,
				     struct tee_ta_param *param)
{
	size_t n;
	void *va;

	/*
	 * If kernel TA is called from another TA the mapping
	 * of that TA is borrowed and the addresses are already
	 * virtual.
	 */
	if (sess != NULL && sess->calling_sess != NULL)
		return TEE_SUCCESS;

	for (n = 0; n < 4; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (core_pa2va((paddr_t)param->params[n].memref.buffer,
				       &va))
				return TEE_ERROR_BAD_PARAMETERS;
			param->params[n].memref.buffer = va;
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

static void tee_ta_set_invoke_timeout(struct tee_ta_session *sess,
				      uint32_t cancel_req_to)
{
	TEE_Time current_time;
	TEE_Time cancel_time = { UINT32_MAX, UINT32_MAX };

	if (cancel_req_to == TEE_TIMEOUT_INFINITE)
		goto out;

	if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		goto out;

	/* Check that it doesn't wrap */
	if (current_time.seconds + (cancel_req_to / 1000) >=
	    current_time.seconds) {
		cancel_time.seconds =
		    current_time.seconds + cancel_req_to / 1000;
		cancel_time.millis = current_time.millis + cancel_req_to % 1000;
		if (cancel_time.millis > 1000) {
			cancel_time.seconds++;
			cancel_time.millis -= 1000;
		}
	}

out:
	sess->cancel_time = cancel_time;
}

static TEE_Result tee_user_ta_enter(TEE_ErrorOrigin *err,
				    struct tee_ta_session *session,
				    enum tee_user_ta_func func,
				    uint32_t cancel_req_to, uint32_t cmd,
				    struct tee_ta_param *param)
{
	TEE_Result res;
	struct abi_user32_param *usr_params;
	tee_paddr_t usr_stack;
	tee_uaddr_t stack_uaddr;
	struct tee_ta_ctx *ctx = session->ctx;
	tee_uaddr_t params_uaddr;
	TEE_ErrorOrigin serr = TEE_ORIGIN_TEE;

	TEE_ASSERT((ctx->flags & TA_FLAG_EXEC_DDR) != 0);

	/* Set timeout of entry */
	tee_ta_set_invoke_timeout(session, cancel_req_to);

	/* Map user space memory */
	res = tee_mmu_map(ctx, param);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	/* Switch to user ctx */
	tee_ta_set_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = tee_mm_get_smem(ctx->mm_stack) + ctx->stack_size;
	usr_stack -= sizeof(struct abi_user32_param);
	usr_params = (struct abi_user32_param *)usr_stack;
	abi_param_to_user32_param(usr_params, param->params, param->types);

	res = tee_mmu_kernel_to_user(ctx, (tee_vaddr_t)usr_params,
				     &params_uaddr);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	res = tee_mmu_kernel_to_user(ctx, usr_stack, &stack_uaddr);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	switch (func) {
	case USER_TA_FUNC_OPEN_CLIENT_SESSION:
		res =
		    thread_enter_user_mode(param->types, params_uaddr,
					   (vaddr_t)session, 0, stack_uaddr,
					   ctx->open_session_func,
					   &ctx->panicked, &ctx->panic_code);

		/*
		 * According to GP spec the origin should allways be set to the
		 * TA after TA execution
		 */
		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	case USER_TA_FUNC_CLOSE_CLIENT_SESSION:
		res = thread_enter_user_mode((vaddr_t)session, 0, 0, 0,
					     stack_uaddr,
					     ctx->close_session_func,
					     &ctx->panicked, &ctx->panic_code);

		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	case USER_TA_FUNC_INVOKE_COMMAND:
		res = thread_enter_user_mode(cmd, param->types, params_uaddr,
					     (vaddr_t)session, stack_uaddr,
					     ctx->invoke_command_func,
					     &ctx->panicked, &ctx->panic_code);

		serr = TEE_ORIGIN_TRUSTED_APP;
		break;

	default:
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_BAD_STATE;
	}

	if (ctx->panicked) {
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x\n",
		     ctx->panic_code);
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

	/* Copy out value results */
	abi_user32_param_to_param(param->params, usr_params, param->types);

cleanup_return:
	/* Restore original ROM mapping */
	tee_ta_set_current_session(NULL);

	/*
	 * Clear the cancel state now that the user TA has returned. The next
	 * time the TA will be invoked will be with a new operation and should
	 * not have an old cancellation pending.
	 */
	session->cancel = false;

	/*
	 * Can't update *err until now since it may point to an address
	 * mapped for the user mode TA.
	 */
	*err = serr;

	return res;
}

/*
 * Load a TA via RPC with UUID defined by input param uuid. The virtual
 * address of the TA is recieved in out parameter ta
 *
 * Function is not thread safe
 */
static TEE_Result tee_ta_rpc_load(const TEE_UUID *uuid,
			struct shdr **ta,
			uint32_t *handle,
			uint32_t *ret_orig)
{
	TEE_Result res;
	struct teesmc32_param params[2];
	paddr_t phpayload = 0;
	paddr_t cookie = 0;
	struct tee_rpc_load_ta_cmd *cmd_load_ta;
	uint32_t lhandle;

	if (!uuid || !ta || !handle || !ret_orig)
		return TEE_ERROR_BAD_PARAMETERS;

	/* get a rpc buffer */
	thread_optee_rpc_alloc_payload(sizeof(struct tee_rpc_load_ta_cmd),
				   &phpayload, &cookie);
	if (!phpayload) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (!TEE_ALIGNMENT_IS_OK(phpayload, struct tee_rpc_load_ta_cmd)) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (core_pa2va(phpayload, &cmd_load_ta)) {
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(params, 0, sizeof(params));
	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INOUT |
			 TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;
	params[1].attr = TEESMC_ATTR_TYPE_MEMREF_OUTPUT |
			 TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT;

	params[0].u.memref.buf_ptr = phpayload;
	params[0].u.memref.size = sizeof(struct tee_rpc_load_ta_cmd);
	params[1].u.memref.buf_ptr = 0;
	params[1].u.memref.size = 0;

	memset(cmd_load_ta, 0, sizeof(struct tee_rpc_load_ta_cmd));
	memcpy(&cmd_load_ta->uuid, uuid, sizeof(TEE_UUID));

	res = thread_rpc_cmd(TEE_RPC_LOAD_TA, 2, params);
	if (res != TEE_SUCCESS) {
		*ret_orig = TEE_ORIGIN_COMMS;
		goto out;
	}

	lhandle = cmd_load_ta->supp_ta_handle;
	if (core_pa2va(params[1].u.memref.buf_ptr, ta)) {
		tee_ta_rpc_free(lhandle);
		*ret_orig = TEE_ORIGIN_TEE;
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	*handle = lhandle;

out:
	thread_optee_rpc_free_payload(cookie);
	return res;
}

static TEE_Result tee_ta_rpc_free(uint32_t handle)
{
	struct teesmc32_param params;

	memset(&params, 0, sizeof(params));
	params.attr = TEESMC_ATTR_TYPE_VALUE_INPUT;
	params.u.value.a = handle;
	return thread_rpc_cmd(TEE_RPC_FREE_TA, 1, &params);
}

static void tee_ta_destroy_context(struct tee_ta_ctx *ctx)
{
	/*
	 * Clean all traces of the TA, both RO and RW data.
	 * No L2 cache maintenance to avoid sync problems
	 */
	if ((ctx->flags & TA_FLAG_EXEC_DDR) != 0) {
		paddr_t pa;
		void *va;
		uint32_t s;

		tee_mmu_set_ctx(ctx);

		if (ctx->mm != NULL) {
			pa = tee_mm_get_smem(ctx->mm);
			if (tee_mmu_user_pa2va(ctx, pa, &va) == TEE_SUCCESS) {
				s = tee_mm_get_bytes(ctx->mm);
				memset(va, 0, s);
				cache_maintenance_l1(DCACHE_AREA_CLEAN, va, s);
			}
		}

		if (ctx->mm_stack) {
			pa = tee_mm_get_smem(ctx->mm_stack);
			if (tee_mmu_user_pa2va(ctx, pa, &va) == TEE_SUCCESS) {
				s = tee_mm_get_bytes(ctx->mm_stack);
				memset(va, 0, s);
				cache_maintenance_l1(DCACHE_AREA_CLEAN, va, s);
			}
		}
		tee_mmu_set_ctx(NULL);
	}

	DMSG("   ... Destroy TA ctx");

	TAILQ_REMOVE(&tee_ctxes, ctx, link);

	/*
	 * Close sessions opened by this TA
	 * Note that tee_ta_close_session() removes the item
	 * from the ctx->open_sessions list.
	 */
	while (!TAILQ_EMPTY(&ctx->open_sessions)) {
		tee_ta_close_session(TAILQ_FIRST(&ctx->open_sessions),
				     &ctx->open_sessions, KERN_IDENTITY);
	}

	if ((ctx->flags & TA_FLAG_USER_MODE) != 0) {
		tee_mmu_final(ctx);
		tee_mm_free(ctx->mm_stack);
	}
	if (ctx->static_ta == NULL) {
		tee_mm_free(ctx->mm);
	}

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(ctx);
	/* Close cryp objects opened by this TA */
	tee_obj_close_all(ctx);
	/* Free emums created by this TA */
	tee_svc_storage_close_all_enum(ctx);

	condvar_destroy(&ctx->busy_cv);

	free(ctx);
}

/* check if requester (client ID) matches session initial client */
static TEE_Result check_client(struct tee_ta_session *s, const TEE_Identity *id)
{
	if (id == KERN_IDENTITY)
		return TEE_SUCCESS;

	if (id == NSAPP_IDENTITY) {
		if (s->clnt_id.login == TEE_LOGIN_TRUSTED_APP) {
			DMSG("nsec tries to hijack TA session");
			return TEE_ERROR_ACCESS_DENIED;
		}
		return TEE_SUCCESS;
	}

	if (memcmp(&s->clnt_id, id, sizeof(TEE_Identity)) != 0) {
		DMSG("client id mismatch");
		return TEE_ERROR_ACCESS_DENIED;
	}
	return TEE_SUCCESS;
}

/*-----------------------------------------------------------------------------
 * Close a Trusted Application and free available resources
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_close_session(struct tee_ta_session *csess,
				struct tee_ta_session_head *open_sessions,
				const TEE_Identity *clnt_id)
{
	struct tee_ta_session *sess;
	struct tee_ta_ctx *ctx;

	DMSG("tee_ta_close_session(0x%" PRIxVA ")",  (vaddr_t)csess);

	if (!csess)
		return TEE_ERROR_ITEM_NOT_FOUND;

	TAILQ_FOREACH(sess, open_sessions, link) {
		if (csess == sess)
			break;
	}
	if (!sess) {
		EMSG("session 0x%" PRIxVA " to removed is not found",
		     (vaddr_t)csess);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (check_client(sess, clnt_id) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS; /* intentional generic error */

	ctx = sess->ctx;
	DMSG("   ... Destroy session");

	tee_ta_set_busy(ctx);

	if (ctx->static_ta) {
		if (ctx->static_ta->close_session_entry_point) {
			DMSG("   ... close_session_entry_point");
			invoke_ta(sess, 0, 0, COMMAND_CLOSE_SESSION);
		}
		if (ctx->ref_count == 1 &&
		    ctx->static_ta->destroy_entry_point) {
			DMSG("   ... destroy_entry_point");
			invoke_ta(sess, 0, 0, COMMAND_DESTROY_ENTRY_POINT);
		}
	} else if (((ctx->flags & TA_FLAG_USER_MODE) != 0) && !ctx->panicked) {
		TEE_ErrorOrigin err;
		struct tee_ta_param param = { 0 };

		tee_user_ta_enter(
			&err, sess,
			USER_TA_FUNC_CLOSE_CLIENT_SESSION,
			TEE_TIMEOUT_INFINITE, 0,
			&param);
	}

	TAILQ_REMOVE(open_sessions, sess, link);
	free(sess);

	tee_ta_clear_busy(ctx);

	TEE_ASSERT(ctx->ref_count > 0);
	ctx->ref_count--;
	if (!ctx->ref_count &&
	    !(ctx->flags & TA_FLAG_INSTANCE_KEEP_ALIVE))
		tee_ta_destroy_context(ctx);

	return TEE_SUCCESS;
}

/*
 * tee_ta_verify_param - check that the 4 "params" match security
 */
static TEE_Result tee_ta_verify_param(struct tee_ta_session *sess,
				      struct tee_ta_param *param)
{
	tee_paddr_t p;
	size_t l;
	int n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:

			p = (tee_paddr_t)param->params[n].memref.buffer;
			l = param->params[n].memref.size;

			if (core_pbuf_is(CORE_MEM_NSEC_SHM, p, l))
				break;
			if ((sess->ctx->flags & TA_FLAG_UNSAFE_NW_PARAMS) &&
				core_pbuf_is(CORE_MEM_MULTPURPOSE, p, l))
				break;
			if ((sess->clnt_id.login == TEE_LOGIN_TRUSTED_APP) &&
				core_pbuf_is(CORE_MEM_TA_RAM, p, l))
				break;

			return TEE_ERROR_SECURITY;
		default:
			break;
		}
	}
	return TEE_SUCCESS;
}

static TEE_Result tee_ta_init_session_with_context(struct tee_ta_ctx *ctx,
			struct tee_ta_session *s)
{
	/*
	 * If TA isn't single instance it should be loaded as new
	 * instance instead of doing anything with this instance.
	 * So tell the caller that we didn't find the TA it the
	 * caller will load a new instance.
	 */
	if ((ctx->flags & TA_FLAG_SINGLE_INSTANCE) == 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/*
	 * The TA is single instance, if it isn't multi session we
	 * can't create another session unless it's the first
	 * new session towards a keepAlive TA.
	 */

	if (((ctx->flags & TA_FLAG_MULTI_SESSION) == 0) &&
	    !(((ctx->flags & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0) &&
	      (ctx->ref_count == 0)))
		return TEE_ERROR_BUSY;

	DMSG("   ... Re-open TA %08x-%04x-%04x",
	     ctx->uuid.timeLow,
	     ctx->uuid.timeMid, ctx->uuid.timeHiAndVersion);


	ctx->ref_count++;
	s->ctx = ctx;
	return TEE_SUCCESS;
}


/*-----------------------------------------------------------------------------
 * Initialises a session based on the UUID or ptr to the ta
 * Returns ptr to the session (ta_session) and a TEE_Result
 *---------------------------------------------------------------------------*/
static TEE_Result tee_ta_init_static_ta_session(const TEE_UUID *uuid,
				struct tee_ta_session *s)
{
	struct tee_ta_ctx *ctx = NULL;
	ta_static_head_t *ta = NULL;

	DMSG("   Lookup for Static TA %08x-%04x-%04x",
	     uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion);

	ta = &__start_ta_head_section;
	while (true) {
		if (ta >= &__stop_ta_head_section)
			return TEE_ERROR_ITEM_NOT_FOUND;
		if (memcmp(&ta->uuid, uuid, sizeof(TEE_UUID)) == 0)
			break;
		ta++;
	}


	/* Load a new TA and create a session */
	DMSG("      Open %s", ta->name);
	ctx = calloc(1, sizeof(struct tee_ta_ctx));
	if (ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	TAILQ_INIT(&ctx->open_sessions);
	TAILQ_INIT(&ctx->cryp_states);
	TAILQ_INIT(&ctx->objects);
	ctx->ref_count = 1;
	s->ctx = ctx;
	ctx->flags = TA_FLAG_MULTI_SESSION;
	ctx->static_ta = ta;
	ctx->uuid = ta->uuid;
	TAILQ_INSERT_TAIL(&tee_ctxes, ctx, link);

	DMSG("      %s : %08x-%04x-%04x",
	     ctx->static_ta->name,
	     ctx->uuid.timeLow,
	     ctx->uuid.timeMid,
	     ctx->uuid.timeHiAndVersion);

	return TEE_SUCCESS;
}

static TEE_Result tee_ta_init_session_with_signed_ta(const TEE_UUID *uuid,
				const struct shdr *signed_ta,
				struct tee_ta_session *s)
{
	TEE_Result res;

	DMSG("   Load dynamic TA");
	/* load and verify */
	res = tee_ta_load(uuid, signed_ta, &s->ctx);
	if (res != TEE_SUCCESS)
		return res;

	DMSG("      dyn TA : %08x-%04x-%04x",
	     s->ctx->uuid.timeLow, s->ctx->uuid.timeMid,
	     s->ctx->uuid.timeHiAndVersion);

	return res;
}

static TEE_Result tee_ta_init_session(TEE_ErrorOrigin *err,
				struct tee_ta_session_head *open_sessions,
				const TEE_UUID *uuid,
				struct tee_ta_session **sess)
{
	TEE_Result res;
	struct tee_ta_ctx *ctx;
	struct shdr *ta = NULL;
	uint32_t handle = 0;
	struct tee_ta_session *s = calloc(1, sizeof(struct tee_ta_session));

	*err = TEE_ORIGIN_TEE;
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;


	s->cancel_mask = true;
	TAILQ_INSERT_TAIL(open_sessions, s, link);
	mutex_lock(&tee_ta_mutex);

	/* Look for already loaded TA */
	ctx = tee_ta_context_find(uuid);
	if (ctx) {
		res = tee_ta_init_session_with_context(ctx, s);
		if (res == TEE_SUCCESS || res != TEE_ERROR_ITEM_NOT_FOUND)
			goto out;
	}

	/* Look for static TA */
	res = tee_ta_init_static_ta_session(uuid, s);
	if (res == TEE_SUCCESS || res != TEE_ERROR_ITEM_NOT_FOUND)
		goto out;

	/* Request TA from tee-supplicant */
	res = tee_ta_rpc_load(uuid, &ta, &handle, err);
	if (res != TEE_SUCCESS)
		goto out;

	res = tee_ta_init_session_with_signed_ta(uuid, ta, s);
	/*
	 * Free normal world shared memory now that the TA either has been
	 * copied into secure memory or the TA failed to be initialized.
	 */
	tee_ta_rpc_free(handle);

out:
	mutex_unlock(&tee_ta_mutex);
	if (res == TEE_SUCCESS) {
		*sess = s;
	} else {
		TAILQ_REMOVE(open_sessions, s, link);
		free(s);
	}
	return res;
}




TEE_Result tee_ta_open_session(TEE_ErrorOrigin *err,
			       struct tee_ta_session **sess,
			       struct tee_ta_session_head *open_sessions,
			       const TEE_UUID *uuid,
			       const TEE_Identity *clnt_id,
			       uint32_t cancel_req_to,
			       struct tee_ta_param *param)
{
	TEE_Result res;
	struct tee_ta_session *s = NULL;
	struct tee_ta_ctx *ctx;
	bool panicked;
	bool was_busy = false;

	res = tee_ta_init_session(err, open_sessions, uuid, &s);
	if (res != TEE_SUCCESS) {
		DMSG("init session failed 0x%x", res);
		return res;
	}

	ctx = s->ctx;

	if (ctx->panicked) {
		DMSG("panicked, call tee_ta_close_session()");
		tee_ta_close_session(s, open_sessions, KERN_IDENTITY);
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}

	*sess = s;
	/* Save identity of the owner of the session */
	s->clnt_id = *clnt_id;

	res = tee_ta_verify_param(s, param);
	if (res == TEE_SUCCESS) {
		if (ctx->static_ta) {
			/* case the static TA */
			if (ctx->ref_count == 1 &&
			    ctx->static_ta->create_entry_point) {
				DMSG("     Call create_entry_point");
				res = invoke_ta(s, 0, 0,
					COMMAND_CREATE_ENTRY_POINT);
			}
			if (ctx->static_ta->open_session_entry_point) {
				res = invoke_ta(s, 0, param,
						COMMAND_OPEN_SESSION);
			}
		} else {
			if (tee_ta_try_set_busy(ctx)) {
				res = tee_user_ta_enter(err, s,
					USER_TA_FUNC_OPEN_CLIENT_SESSION,
					cancel_req_to, 0, param);
				tee_ta_clear_busy(ctx);
			} else {
				/* Deadlock avoided */
				res = TEE_ERROR_BUSY;
				was_busy = true;
			}
		}
	}

	panicked = ctx->panicked;

	if (panicked || (res != TEE_SUCCESS))
		tee_ta_close_session(s, open_sessions, KERN_IDENTITY);

	/*
	 * Origin error equal to TEE_ORIGIN_TRUSTED_APP for "regular" error,
	 * apart from panicking.
	 */
	if (panicked || was_busy)
		*err = TEE_ORIGIN_TEE;
	else
		*err = TEE_ORIGIN_TRUSTED_APP;

	if (res != TEE_SUCCESS)
		EMSG("Failed. Return error 0x%x", res);

	return res;
}

TEE_Result tee_ta_invoke_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id,
				 uint32_t cancel_req_to, uint32_t cmd,
				 struct tee_ta_param *param)
{
	TEE_Result res;

	if (check_client(sess, clnt_id) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS; /* intentional generic error */

	if (sess->ctx->panicked) {
		DMSG("   Panicked !");
		*err = TEE_ORIGIN_TEE;
		OUTRMSG(TEE_ERROR_TARGET_DEAD);
	}

	tee_ta_set_busy(sess->ctx);

	res = tee_ta_verify_param(sess, param);
	if (res != TEE_SUCCESS) {
		*err = TEE_ORIGIN_TEE;
		goto function_exit;
	}

	if (sess->ctx->static_ta) {
		if (sess->ctx->static_ta->invoke_command_entry_point) {
			res = tee_ta_param_pa2va(sess, param);
			if (res != TEE_SUCCESS) {
				*err = TEE_ORIGIN_TEE;
				goto function_exit;
			}

			/* Set timeout of entry */
			tee_ta_set_invoke_timeout(sess, cancel_req_to);

			DMSG("   invoke_command_entry_point(%p)",
				sess->user_ctx);
			res = invoke_ta(sess, cmd, param,
					COMMAND_INVOKE_COMMAND);

			/*
			 * According to GP spec the origin should allways
			 * be set to the TA after TA execution
			 */
			*err = TEE_ORIGIN_TRUSTED_APP;
		} else {
			*err = TEE_ORIGIN_TEE;
			res = TEE_ERROR_GENERIC;
			/*
			 * The static TA hasn't been invoked since the last
			 * check for panic it would be just redundant to
			 * check again.
			 */
			goto function_exit;
		}

	} else if ((sess->ctx->flags & TA_FLAG_USER_MODE) != 0) {
		res = tee_user_ta_enter(err, sess, USER_TA_FUNC_INVOKE_COMMAND,
					cancel_req_to, cmd, param);
	} else {
		EMSG("only user TA are supported");
		*err = TEE_ORIGIN_TEE;
		res = TEE_ERROR_NOT_SUPPORTED;
		goto function_exit;
	}

	if (sess->ctx->panicked) {
		*err = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

function_exit:
	tee_ta_clear_busy(sess->ctx);
	if (res != TEE_SUCCESS)
		DMSG("  => Error: %x of %d\n", res, *err);
	return res;
}

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id)
{
	*err = TEE_ORIGIN_TEE;

	if (check_client(sess, clnt_id) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS; /* intentional generic error */

	sess->cancel = true;
	return TEE_SUCCESS;
}

TEE_Result tee_ta_get_current_session(struct tee_ta_session **sess)
{
	struct tee_ta_session *tee_rs = get_tee_rs();

	if (tee_rs == NULL)
		return TEE_ERROR_BAD_STATE;
	*sess = tee_rs;
	return TEE_SUCCESS;
}

void tee_ta_set_current_session(struct tee_ta_session *sess)
{
	if (get_tee_rs() != sess) {
		struct tee_ta_ctx *ctx = NULL;

		if (sess != NULL)
			ctx = sess->ctx;

		set_tee_rs(sess);
		tee_mmu_set_ctx(ctx);
	}
	/*
	 * If sess == NULL we must not have user mapping active,
	 * if sess != NULL we must have have user mapping active.
	 */
	assert((sess == NULL) == !core_mmu_user_mapping_is_active());
}

TEE_Result tee_ta_get_client_id(TEE_Identity *id)
{
	TEE_Result res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	if (id == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	*id = sess->clnt_id;
	return TEE_SUCCESS;
}

TEE_Result tee_ta_verify_session_pointer(struct tee_ta_session *sess,
					 struct tee_ta_session_head
					 *open_sessions)
{
	struct tee_ta_session *s;

	if (sess == (struct tee_ta_session *)TEE_SESSION_ID_STATIC_TA)
		return TEE_SUCCESS;

	TAILQ_FOREACH(s, open_sessions, link) {
		if (s == sess)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

/*
 * tee_uta_cache_operation - dynamic cache clean/inval request from a TA
 * It follows ARM recommendation:
 *     http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0246d/Beicdhde.html
 * Note that this implementation assumes dsb operations are part of
 * cache_maintenance_l1(), and L2 cache sync are part of
 * cache_maintenance_l2()
 */
#ifdef CFG_CACHE_API
TEE_Result tee_uta_cache_operation(struct tee_ta_session *sess,
				   enum utee_cache_operation op,
				   void *va, size_t len)
{
	TEE_Result ret;
	paddr_t pa = 0;

	if ((sess->ctx->flags & TA_FLAG_CACHE_MAINTENANCE) == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	ret = tee_mmu_check_access_rights(sess->ctx,
			TEE_MEMORY_ACCESS_WRITE, (tee_uaddr_t)va, len);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	ret = tee_mmu_user_va2pa(sess->ctx, va, &pa);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	switch (op) {
	case TEE_CACHEFLUSH:
		/* Clean L1, Flush L2, Flush L1 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return ret;
		ret = cache_maintenance_l2(L2CACHE_AREA_CLEAN_INV, pa, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l1(DCACHE_AREA_CLEAN_INV, va, len);

	case TEE_CACHECLEAN:
		/* Clean L1, Clean L2 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l2(L2CACHE_AREA_CLEAN, pa, len);

	case TEE_CACHEINVALIDATE:
		/* Inval L2, Inval L1 */
		ret = cache_maintenance_l2(L2CACHE_AREA_INVALIDATE, pa, len);
		if (ret != TEE_SUCCESS)
			return ret;
		return cache_maintenance_l1(DCACHE_AREA_INVALIDATE, va, len);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
#endif

/*
 * dump_state - Display TA state as an error log.
 */
static void dump_state(struct tee_ta_ctx *ctx)
{
	struct tee_ta_session *s = NULL;
	char uuid[TEE_UUID_STRING_LEN];
	bool active __unused;

	uuid2str(uuid, &ctx->uuid);
	active = ((tee_ta_get_current_session(&s) == TEE_SUCCESS) &&
		  s && s->ctx == ctx);

	EMSG_RAW("Status of TA %s (%p)", uuid, (void *)ctx);
	EMSG_RAW("- load addr : 0x%x    ctx-idr: %d     %s",
		 ctx->load_addr, ctx->context, active ? "(active)" : "");
	EMSG_RAW("- code area : 0x%" PRIxPTR " %zu",
		 tee_mm_get_smem(ctx->mm), tee_mm_get_bytes(ctx->mm));
	EMSG_RAW("- stack: 0x%" PRIxPTR " stack:%zu",
		 tee_mm_get_smem(ctx->mm_stack), ctx->stack_size);
}

void tee_ta_dump_current(void)
{
	struct tee_ta_session *s = NULL;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS) {
		EMSG("no valid session found, cannot log TA status");
		return;
	}

	dump_state(s->ctx);
}

void tee_ta_dump_all(void)
{
	struct tee_ta_ctx *ctx;

	TAILQ_FOREACH(ctx, &tee_ctxes, link)
		dump_state(ctx);
}
