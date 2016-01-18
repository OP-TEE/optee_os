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
#include <types_ext.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arm.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/static_ta.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/tee_mmu.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_storage.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>
#include <util.h>
#include <assert.h>

/* This mutex protects the critical section in tee_ta_init_session */
static struct mutex tee_ta_mutex = MUTEX_INITIALIZER;
static struct condvar tee_ta_cv = CONDVAR_INITIALIZER;
static int tee_ta_single_instance_thread = THREAD_ID_INVALID;
static size_t tee_ta_single_instance_count;

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

static void dec_session_ref_count(struct tee_ta_session *s)
{
	assert(s->ref_count > 0);
	s->ref_count--;
	if (s->ref_count == 1)
		condvar_signal(&s->refc_cv);
}

void tee_ta_put_session(struct tee_ta_session *s)
{
	mutex_lock(&tee_ta_mutex);

	if (s->lock_thread == thread_get_id()) {
		s->lock_thread = THREAD_ID_INVALID;
		condvar_signal(&s->lock_cv);
	}
	dec_session_ref_count(s);

	mutex_unlock(&tee_ta_mutex);
}

static struct tee_ta_session *find_session(uint32_t id,
			struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *s;

	TAILQ_FOREACH(s, open_sessions, link) {
		if ((vaddr_t)s == id)
			return s;
	}
	return NULL;
}

struct tee_ta_session *tee_ta_get_session(uint32_t id, bool exclusive,
			struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *s;

	mutex_lock(&tee_ta_mutex);

	while (true) {
		s = find_session(id, open_sessions);
		if (!s)
			break;
		if (s->unlink) {
			s = NULL;
			break;
		}
		s->ref_count++;
		if (!exclusive)
			break;

		assert(s->lock_thread != thread_get_id());

		while (s->lock_thread != THREAD_ID_INVALID && !s->unlink)
			condvar_wait(&s->lock_cv, &tee_ta_mutex);

		if (s->unlink) {
			dec_session_ref_count(s);
			s = NULL;
			break;
		}

		s->lock_thread = thread_get_id();
		break;
	}

	mutex_unlock(&tee_ta_mutex);
	return s;
}

static void tee_ta_unlink_session(struct tee_ta_session *s,
			struct tee_ta_session_head *open_sessions)
{
	mutex_lock(&tee_ta_mutex);

	assert(s->ref_count >= 1);
	assert(s->lock_thread == thread_get_id());
	assert(!s->unlink);

	s->unlink = true;
	condvar_broadcast(&s->lock_cv);

	while (s->ref_count != 1)
		condvar_wait(&s->refc_cv, &tee_ta_mutex);

	TAILQ_REMOVE(open_sessions, s, link);

	mutex_unlock(&tee_ta_mutex);
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

static void set_invoke_timeout(struct tee_ta_session *sess,
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

	sess = tee_ta_get_session((vaddr_t)csess, true, open_sessions);

	if (!sess) {
		EMSG("session 0x%" PRIxVA " to be removed is not found",
		     (vaddr_t)csess);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (check_client(sess, clnt_id) != TEE_SUCCESS) {
		tee_ta_put_session(sess);
		return TEE_ERROR_BAD_PARAMETERS; /* intentional generic error */
	}

	ctx = sess->ctx;
	DMSG("   ... Destroy session");

	tee_ta_set_busy(ctx);

	if (!ctx->panicked) {
		set_invoke_timeout(sess, TEE_TIMEOUT_INFINITE);
		ctx->ops->enter_close_session(sess);
	}

	tee_ta_unlink_session(sess, open_sessions);
	free(sess);

	tee_ta_clear_busy(ctx);

	mutex_lock(&tee_ta_mutex);

	TEE_ASSERT(ctx->ref_count > 0);
	ctx->ref_count--;
	if (!ctx->ref_count && !(ctx->flags & TA_FLAG_INSTANCE_KEEP_ALIVE)) {
		DMSG("   ... Destroy TA ctx");

		TAILQ_REMOVE(&tee_ctxes, ctx, link);
		mutex_unlock(&tee_ta_mutex);

		condvar_destroy(&ctx->busy_cv);

		ctx->ops->destroy(ctx);
	} else
		mutex_unlock(&tee_ta_mutex);

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

	DMSG("   ... Re-open TA %pUl", (void *)&ctx->uuid);

	ctx->ref_count++;
	s->ctx = ctx;
	return TEE_SUCCESS;
}



static TEE_Result tee_ta_init_session(TEE_ErrorOrigin *err,
				struct tee_ta_session_head *open_sessions,
				const TEE_UUID *uuid,
				struct tee_ta_session **sess)
{
	TEE_Result res;
	struct tee_ta_ctx *ctx;
	struct tee_ta_session *s = calloc(1, sizeof(struct tee_ta_session));

	*err = TEE_ORIGIN_TEE;
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->cancel_mask = true;
	condvar_init(&s->refc_cv);
	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;
	s->ref_count = 1;


	/*
	 * We take the global TA mutex here and hold it while doing
	 * RPC to load the TA. This big critical section should be broken
	 * down into smaller pieces.
	 */


	mutex_lock(&tee_ta_mutex);
	TAILQ_INSERT_TAIL(open_sessions, s, link);

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

	/* Look for user TA */
	res = tee_ta_init_user_ta_session(uuid, s);

out:
	if (res == TEE_SUCCESS) {
		*sess = s;
	} else {
		TAILQ_REMOVE(open_sessions, s, link);
		free(s);
	}
	mutex_unlock(&tee_ta_mutex);
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
		if (tee_ta_try_set_busy(ctx)) {
			set_invoke_timeout(s, cancel_req_to);
			res = ctx->ops->enter_open_session(s, param, err);
			tee_ta_clear_busy(ctx);
		} else {
			/* Deadlock avoided */
			res = TEE_ERROR_BUSY;
			was_busy = true;
		}
	}

	panicked = ctx->panicked;

	tee_ta_put_session(s);
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
		return TEE_ERROR_TARGET_DEAD;
	}

	tee_ta_set_busy(sess->ctx);

	res = tee_ta_verify_param(sess, param);
	if (res != TEE_SUCCESS) {
		*err = TEE_ORIGIN_TEE;
		goto function_exit;
	}

	set_invoke_timeout(sess, cancel_req_to);
	res = sess->ctx->ops->enter_invoke_cmd(sess, cmd, param, err);

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
	struct tee_ta_session *tee_rs = thread_get_tsd();

	if (tee_rs == NULL)
		return TEE_ERROR_BAD_STATE;
	*sess = tee_rs;
	return TEE_SUCCESS;
}

void tee_ta_set_current_session(struct tee_ta_session *sess)
{
	struct tee_ta_ctx *ctx = NULL;

	if (sess) {
		if (sess->calling_sess)
			ctx = sess->calling_sess->ctx;
		else
			ctx = sess->ctx;
	}

	if (thread_get_tsd() != sess) {
		thread_set_tsd(sess);
		tee_mmu_set_ctx(ctx);
	}
	/*
	 * If ctx->mmu == NULL we must not have user mapping active,
	 * if ctx->mmu != NULL we must have user mapping active.
	 */
	assert(((ctx && (ctx->flags & TA_FLAG_USER_MODE) ?
			to_user_ta_ctx(ctx)->mmu : NULL) == NULL) ==
		!core_mmu_user_mapping_is_active());
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
	struct user_ta_ctx *utc;

	if ((sess->ctx->flags & TA_FLAG_CACHE_MAINTENANCE) == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	utc = to_user_ta_ctx(sess->ctx);
	ret = tee_mmu_check_access_rights(utc,
			TEE_MEMORY_ACCESS_WRITE, (tee_uaddr_t)va, len);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	ret = tee_mmu_user_va2pa(utc, va, &pa);
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
	bool active __unused;

	active = ((tee_ta_get_current_session(&s) == TEE_SUCCESS) &&
		  s && s->ctx == ctx);

	EMSG_RAW("Status of TA %pUl (%p) %s", (void *)&ctx->uuid, (void *)ctx,
		active ? "(active)" : "");
	ctx->ops->dump_state(ctx);
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
