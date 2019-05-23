// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <types_ext.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arm.h>
#include <assert.h>
#include <kernel/ftrace.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_time.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mmu.h>
#include <tee/entry_std.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_storage.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_types.h>
#include <util.h>

/* This mutex protects the critical section in tee_ta_init_session */
struct mutex tee_ta_mutex = MUTEX_INITIALIZER;
struct tee_ta_ctx_head tee_ctxes = TAILQ_HEAD_INITIALIZER(tee_ctxes);

#ifndef CFG_CONCURRENT_SINGLE_INSTANCE_TA
static struct condvar tee_ta_cv = CONDVAR_INITIALIZER;
static int tee_ta_single_instance_thread = THREAD_ID_INVALID;
static size_t tee_ta_single_instance_count;
#endif

#ifdef CFG_CONCURRENT_SINGLE_INSTANCE_TA
static void lock_single_instance(void)
{
}

static void unlock_single_instance(void)
{
}

static bool has_single_instance_lock(void)
{
	return false;
}
#else
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
#endif

static bool tee_ta_try_set_busy(struct tee_ta_ctx *ctx)
{
	bool rc = true;

	if (ctx->flags & TA_FLAG_CONCURRENT)
		return true;

	mutex_lock(&tee_ta_mutex);

	if (ctx->initializing) {
		/*
		 * Context is still initializing and flags cannot be relied
		 * on for user TAs. Wait here until it's initialized.
		 */
		while (ctx->busy)
			condvar_wait(&ctx->busy_cv, &tee_ta_mutex);
	}

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
	if (ctx->flags & TA_FLAG_CONCURRENT)
		return;

	mutex_lock(&tee_ta_mutex);

	assert(ctx->busy);
	ctx->busy = false;
	condvar_signal(&ctx->busy_cv);

	if (!ctx->initializing && (ctx->flags & TA_FLAG_SINGLE_INSTANCE))
		unlock_single_instance();

	ctx->initializing = false;

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

static struct tee_ta_session *tee_ta_find_session_nolock(uint32_t id,
			struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *s = NULL;
	struct tee_ta_session *found = NULL;

	TAILQ_FOREACH(s, open_sessions, link) {
		if (s->id == id) {
			found = s;
			break;
		}
	}

	return found;
}

struct tee_ta_session *tee_ta_find_session(uint32_t id,
			struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *s = NULL;

	mutex_lock(&tee_ta_mutex);

	s = tee_ta_find_session_nolock(id, open_sessions);

	mutex_unlock(&tee_ta_mutex);

	return s;
}

struct tee_ta_session *tee_ta_get_session(uint32_t id, bool exclusive,
			struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *s;

	mutex_lock(&tee_ta_mutex);

	while (true) {
		s = tee_ta_find_session_nolock(id, open_sessions);
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

static void destroy_session(struct tee_ta_session *s,
			    struct tee_ta_session_head *open_sessions)
{
#if defined(CFG_TA_FTRACE_SUPPORT)
	if (s->ctx) {
		tee_ta_push_current_session(s);
		ta_fbuf_dump(s);
		tee_ta_pop_current_session();
	}
#endif

	tee_ta_unlink_session(s, open_sessions);
#if defined(CFG_TA_GPROF_SUPPORT)
	free(s->sbuf);
#endif
	free(s);
}

static void destroy_context(struct tee_ta_ctx *ctx)
{
	DMSG("Destroy TA ctx (0x%" PRIxVA ")",  (vaddr_t)ctx);

	condvar_destroy(&ctx->busy_cv);
	pgt_flush_ctx(ctx);
	ctx->ops->destroy(ctx);
}

static void destroy_ta_ctx_from_session(struct tee_ta_session *s)
{
	struct tee_ta_session *sess = NULL;
	struct tee_ta_session_head *open_sessions = NULL;
	struct tee_ta_ctx *ctx = NULL;
	struct user_ta_ctx *utc = NULL;
	size_t count = 1; /* start counting the references to the context */

	DMSG("Remove references to context (0x%" PRIxVA ")", (vaddr_t)s->ctx);

	mutex_lock(&tee_ta_mutex);
	nsec_sessions_list_head(&open_sessions);

	/*
	 * Next two loops will remove all references to the context which is
	 * about to be destroyed, but avoiding such operation to the current
	 * session. That will be done later in this function, only after
	 * the context will be properly destroyed.
	 */

	/*
	 * Scan the entire list of opened sessions by the clients from
	 * non-secure world.
	 */
	TAILQ_FOREACH(sess, open_sessions, link) {
		if (sess->ctx == s->ctx && sess != s) {
			sess->ctx = NULL;
			count++;
		}
	}

	/*
	 * Scan all sessions opened from secure side by searching through
	 * all available TA instances and for each context, scan all opened
	 * sessions.
	 */
	TAILQ_FOREACH(ctx, &tee_ctxes, link) {
		if (is_user_ta_ctx(ctx)) {
			utc = to_user_ta_ctx(ctx);

			TAILQ_FOREACH(sess, &utc->open_sessions, link) {
				if (sess->ctx == s->ctx && sess != s) {
					sess->ctx = NULL;
					count++;
				}
			}
		}
	}

	assert(count == s->ctx->ref_count);

	TAILQ_REMOVE(&tee_ctxes, s->ctx, link);
	mutex_unlock(&tee_ta_mutex);

	destroy_context(s->ctx);

	s->ctx = NULL;
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

/*
 * Check if invocation parameters matches TA properties
 *
 * @s - current session handle
 * @param - already identified memory references hold a valid 'mobj'.
 *
 * Policy:
 * - All TAs can access 'non-secure' shared memory.
 * - All TAs can access TEE private memory (seccpy)
 * - Only SDP flagged TAs can accept SDP memory references.
 */
#ifndef CFG_SECURE_DATA_PATH
static bool check_params(struct tee_ta_session *sess __unused,
			 struct tee_ta_param *param __unused)
{
	/*
	 * When CFG_SECURE_DATA_PATH is not enabled, SDP memory references
	 * are rejected at OP-TEE core entry. Hence here all TAs have same
	 * permissions regarding memory reference parameters.
	 */
	return true;
}
#else
static bool check_params(struct tee_ta_session *sess,
			 struct tee_ta_param *param)
{
	int n;

	/*
	 * When CFG_SECURE_DATA_PATH is enabled, OP-TEE entry allows SHM and
	 * SDP memory references. Only TAs flagged SDP can access SDP memory.
	 */
	if (sess->ctx && sess->ctx->flags & TA_FLAG_SECURE_DATA_PATH)
		return true;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uint32_t param_type = TEE_PARAM_TYPE_GET(param->types, n);
		struct param_mem *mem = &param->u[n].mem;

		if (param_type != TEE_PARAM_TYPE_MEMREF_INPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
		    param_type != TEE_PARAM_TYPE_MEMREF_INOUT)
			continue;
		if (!mem->size)
			continue;
		if (mobj_is_sdp_mem(mem->mobj))
			return false;
	}
	return true;
}
#endif

static void set_invoke_timeout(struct tee_ta_session *sess,
				      uint32_t cancel_req_to)
{
	TEE_Time current_time;
	TEE_Time cancel_time;

	if (cancel_req_to == TEE_TIMEOUT_INFINITE)
		goto infinite;

	if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		goto infinite;

	if (ADD_OVERFLOW(current_time.seconds, cancel_req_to / 1000,
			 &cancel_time.seconds))
		goto infinite;

	cancel_time.millis = current_time.millis + cancel_req_to % 1000;
	if (cancel_time.millis > 1000) {
		if (ADD_OVERFLOW(current_time.seconds, 1,
				 &cancel_time.seconds))
			goto infinite;

		cancel_time.seconds++;
		cancel_time.millis -= 1000;
	}

	sess->cancel_time = cancel_time;
	return;

infinite:
	sess->cancel_time.seconds = UINT32_MAX;
	sess->cancel_time.millis = UINT32_MAX;
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
	bool keep_alive;

	DMSG("csess 0x%" PRIxVA " id %u", (vaddr_t)csess, csess->id);

	if (!csess)
		return TEE_ERROR_ITEM_NOT_FOUND;

	sess = tee_ta_get_session(csess->id, true, open_sessions);

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
	DMSG("Destroy session");

	if (!ctx) {
		destroy_session(sess, open_sessions);
		return TEE_SUCCESS;
	}

	if (ctx->panicked) {
		destroy_session(sess, open_sessions);
	} else {
		tee_ta_set_busy(ctx);
		set_invoke_timeout(sess, TEE_TIMEOUT_INFINITE);
		ctx->ops->enter_close_session(sess);
		destroy_session(sess, open_sessions);
		tee_ta_clear_busy(ctx);
	}

	mutex_lock(&tee_ta_mutex);

	if (ctx->ref_count <= 0)
		panic();

	ctx->ref_count--;
	keep_alive = (ctx->flags & TA_FLAG_INSTANCE_KEEP_ALIVE) &&
			(ctx->flags & TA_FLAG_SINGLE_INSTANCE);
	if (!ctx->ref_count && !keep_alive) {
		TAILQ_REMOVE(&tee_ctxes, ctx, link);
		mutex_unlock(&tee_ta_mutex);

		destroy_context(ctx);
	} else
		mutex_unlock(&tee_ta_mutex);

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
	 * can't create another session unless its reference is zero
	 */
	if (!(ctx->flags & TA_FLAG_MULTI_SESSION) && ctx->ref_count)
		return TEE_ERROR_BUSY;

	DMSG("Re-open TA %pUl", (void *)&ctx->uuid);

	ctx->ref_count++;
	s->ctx = ctx;
	return TEE_SUCCESS;
}

static uint32_t new_session_id(struct tee_ta_session_head *open_sessions)
{
	struct tee_ta_session *last = NULL;
	uint32_t saved = 0;
	uint32_t id = 1;

	last = TAILQ_LAST(open_sessions, tee_ta_session_head);
	if (last) {
		/* This value is less likely to be already used */
		id = last->id + 1;
		if (!id)
			id++; /* 0 is not valid */
	}

	saved = id;
	do {
		if (!tee_ta_find_session_nolock(id, open_sessions))
			return id;
		id++;
		if (!id)
			id++;
	} while (id != saved);

	return 0;
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
	s->id = new_session_id(open_sessions);
	if (!s->id) {
		res = TEE_ERROR_OVERFLOW;
		goto out;
	}
	TAILQ_INSERT_TAIL(open_sessions, s, link);

	/* Look for already loaded TA */
	ctx = tee_ta_context_find(uuid);
	if (ctx) {
		res = tee_ta_init_session_with_context(ctx, s);
		if (res == TEE_SUCCESS || res != TEE_ERROR_ITEM_NOT_FOUND)
			goto out;
	}

	/* Look for pseudo TA */
	res = tee_ta_init_pseudo_ta_session(uuid, s);
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

	if (!check_params(s, param))
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = s->ctx;

	if (!ctx || ctx->panicked) {
		DMSG("panicked, call tee_ta_close_session()");
		tee_ta_close_session(s, open_sessions, KERN_IDENTITY);
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}

	*sess = s;
	/* Save identity of the owner of the session */
	s->clnt_id = *clnt_id;

	if (tee_ta_try_set_busy(ctx)) {
		set_invoke_timeout(s, cancel_req_to);
		res = ctx->ops->enter_open_session(s, param, err);
		tee_ta_clear_busy(ctx);
	} else {
		/* Deadlock avoided */
		res = TEE_ERROR_BUSY;
		was_busy = true;
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

	if (!check_params(sess, param))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!sess->ctx) {
		/* The context has been already destroyed */
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	} else if (sess->ctx->panicked) {
		DMSG("Panicked !");
		destroy_ta_ctx_from_session(sess);
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}

	tee_ta_set_busy(sess->ctx);

	set_invoke_timeout(sess, cancel_req_to);
	res = sess->ctx->ops->enter_invoke_cmd(sess, cmd, param, err);

	tee_ta_clear_busy(sess->ctx);

	if (sess->ctx->panicked) {
		destroy_ta_ctx_from_session(sess);
		*err = TEE_ORIGIN_TEE;
		return TEE_ERROR_TARGET_DEAD;
	}

	/* Short buffer is not an effective error case */
	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)
		DMSG("Error: %x of %d", res, *err);

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

bool tee_ta_session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time)
{
	TEE_Time current_time;

	if (s->cancel_mask)
		return false;

	if (s->cancel)
		return true;

	if (s->cancel_time.seconds == UINT32_MAX)
		return false;

	if (curr_time != NULL)
		current_time = *curr_time;
	else if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
		return false;

	if (current_time.seconds > s->cancel_time.seconds ||
	    (current_time.seconds == s->cancel_time.seconds &&
	     current_time.millis >= s->cancel_time.millis)) {
		return true;
	}

	return false;
}

static void update_current_ctx(struct thread_specific_data *tsd)
{
	struct tee_ta_ctx *ctx = NULL;
	struct tee_ta_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		if (is_pseudo_ta_ctx(s->ctx))
			s = TAILQ_NEXT(s, link_tsd);

		if (s)
			ctx = s->ctx;
	}

	if (tsd->ctx != ctx)
		tee_mmu_set_ctx(ctx);
	/*
	 * If ctx->mmu == NULL we must not have user mapping active,
	 * if ctx->mmu != NULL we must have user mapping active.
	 */
	if (((is_user_ta_ctx(ctx) ?
			to_user_ta_ctx(ctx)->vm_info : NULL) == NULL) ==
					core_mmu_user_mapping_is_active())
		panic("unexpected active mapping");
}

void tee_ta_push_current_session(struct tee_ta_session *sess)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	TAILQ_INSERT_HEAD(&tsd->sess_stack, sess, link_tsd);
	update_current_ctx(tsd);
}

struct tee_ta_session *tee_ta_pop_current_session(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_ta_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		TAILQ_REMOVE(&tsd->sess_stack, s, link_tsd);
		update_current_ctx(tsd);
	}
	return s;
}

TEE_Result tee_ta_get_current_session(struct tee_ta_session **sess)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (!s)
		return TEE_ERROR_BAD_STATE;
	*sess = s;
	return TEE_SUCCESS;
}

struct tee_ta_session *tee_ta_get_calling_session(void)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s)
		s = TAILQ_NEXT(s, link_tsd);
	return s;
}

#if defined(CFG_TA_GPROF_SUPPORT)
void tee_ta_gprof_sample_pc(vaddr_t pc)
{
	struct tee_ta_session *s;
	struct sample_buf *sbuf;
	size_t idx;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		return;
	sbuf = s->sbuf;
	if (!sbuf || !sbuf->enabled)
		return; /* PC sampling is not enabled */

	idx = (((uint64_t)pc - sbuf->offset)/2 * sbuf->scale)/65536;
	if (idx < sbuf->nsamples)
		sbuf->samples[idx]++;
	sbuf->count++;
}

/*
 * Update user-mode CPU time for the current session
 * @suspend: true if session is being suspended (leaving user mode), false if
 * it is resumed (entering user mode)
 */
static void tee_ta_update_session_utime(bool suspend)
{
	struct tee_ta_session *s;
	struct sample_buf *sbuf;
	uint64_t now;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		return;
	sbuf = s->sbuf;
	if (!sbuf)
		return;
	now = read_cntpct();
	if (suspend) {
		assert(sbuf->usr_entered);
		sbuf->usr += now - sbuf->usr_entered;
		sbuf->usr_entered = 0;
	} else {
		assert(!sbuf->usr_entered);
		if (!now)
			now++; /* 0 is reserved */
		sbuf->usr_entered = now;
	}
}

void tee_ta_update_session_utime_suspend(void)
{
	tee_ta_update_session_utime(true);
}

void tee_ta_update_session_utime_resume(void)
{
	tee_ta_update_session_utime(false);
}
#endif
