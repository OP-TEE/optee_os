/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#ifndef TEE_TA_MANAGER_H
#define TEE_TA_MANAGER_H

#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/tee_common.h>
#include <kernel/ts_manager.h>
#include <mm/tee_mmu_types.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <user_ta_header.h>
#include <utee_types.h>

/* Magic TEE identity pointer: set when teecore requests a TA close */
#define KERN_IDENTITY	((TEE_Identity *)-1)
/* Operation is initiated by a client (non-secure) app */
#define NSAPP_IDENTITY	(NULL)

TAILQ_HEAD(tee_ta_session_head, tee_ta_session);
TAILQ_HEAD(tee_ta_ctx_head, tee_ta_ctx);

struct mobj;

struct param_val {
	uint32_t a;
	uint32_t b;
};

struct param_mem {
	struct mobj *mobj;
	size_t size;
	size_t offs;
};

struct tee_ta_param {
	uint32_t types;
	union {
		struct param_val val;
		struct param_mem mem;
	} u[TEE_NUM_PARAMS];
};

struct user_ta_ctx;

#if defined(CFG_TA_GPROF_SUPPORT)
struct sample_buf {
	uint32_t nsamples;	/* Size of @samples array in uint16_t */
	uint32_t offset;	/* Passed from user mode */
	uint32_t scale;		/* Passed from user mode */
	uint32_t count;		/* Number of samples taken */
	bool enabled;		/* Sampling enabled? */
	uint16_t *samples;
	uint64_t usr;		/* Total user CPU time for this session */
	uint64_t usr_entered;	/* When this session last entered user mode */
	uint32_t freq;		/* @usr divided by @freq is in seconds */
};
#endif

/* Context of a loaded TA */
struct tee_ta_ctx {
	uint32_t flags;		/* TA_FLAGS from TA header */
	TAILQ_ENTRY(tee_ta_ctx) link;
	struct ts_ctx ts_ctx;
	uint32_t panicked;	/* True if TA has panicked, written from asm */
	uint32_t panic_code;	/* Code supplied for panic */
	uint32_t ref_count;	/* Reference counter for multi session TA */
	bool busy;		/* Context is busy and cannot be entered */
	struct condvar busy_cv;	/* CV used when context is busy */
};

struct tee_ta_session {
	TAILQ_ENTRY(tee_ta_session) link;
	struct ts_session ts_sess;
	uint32_t id;		/* Session handle (0 is invalid) */
	TEE_Identity clnt_id;	/* Identify of client */
	struct tee_ta_param *param;
	TEE_ErrorOrigin err_origin;
	bool cancel;		/* True if TA invocation is cancelled */
	bool cancel_mask;	/* True if cancel is masked */
	TEE_Time cancel_time;	/* Time when to cancel the TA invocation */
	uint32_t ref_count;	/* reference counter */
	struct condvar refc_cv;	/* CV used to wait for ref_count to be 0 */
	struct condvar lock_cv;	/* CV used to wait for lock */
	short int lock_thread;	/* Id of thread holding the lock */
	bool unlink;		/* True if session is to be unlinked */
};

/* Registered contexts */
extern struct tee_ta_ctx_head tee_ctxes;

extern struct mutex tee_ta_mutex;
extern struct condvar tee_ta_init_cv;

TEE_Result tee_ta_open_session(TEE_ErrorOrigin *err,
			       struct tee_ta_session **sess,
			       struct tee_ta_session_head *open_sessions,
			       const TEE_UUID *uuid,
			       const TEE_Identity *clnt_id,
			       uint32_t cancel_req_to,
			       struct tee_ta_param *param);

TEE_Result tee_ta_invoke_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id,
				 uint32_t cancel_req_to, uint32_t cmd,
				 struct tee_ta_param *param);

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id);

bool tee_ta_session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time);

/*-----------------------------------------------------------------------------
 * Function called to close a TA.
 * Parameters:
 * id   - The session id (in)
 * Returns:
 *        TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_close_session(struct tee_ta_session *sess,
				struct tee_ta_session_head *open_sessions,
				const TEE_Identity *clnt_id);



struct tee_ta_session *tee_ta_find_session(uint32_t id,
			struct tee_ta_session_head *open_sessions);

struct tee_ta_session *tee_ta_get_session(uint32_t id, bool exclusive,
			struct tee_ta_session_head *open_sessions);

void tee_ta_put_session(struct tee_ta_session *sess);

#if defined(CFG_TA_GPROF_SUPPORT)
void tee_ta_update_session_utime_suspend(void);
void tee_ta_update_session_utime_resume(void);
void tee_ta_gprof_sample_pc(vaddr_t pc);
#else
static inline void tee_ta_update_session_utime_suspend(void) {}
static inline void tee_ta_update_session_utime_resume(void) {}
static inline void tee_ta_gprof_sample_pc(vaddr_t pc __unused) {}
#endif
#if defined(CFG_FTRACE_SUPPORT)
void tee_ta_ftrace_update_times_suspend(void);
void tee_ta_ftrace_update_times_resume(void);
#else
static inline void tee_ta_ftrace_update_times_suspend(void) {}
static inline void tee_ta_ftrace_update_times_resume(void) {}
#endif

bool is_ta_ctx(struct ts_ctx *ctx);

struct tee_ta_session *to_ta_session(struct ts_session *sess);

static inline struct tee_ta_ctx *to_ta_ctx(struct ts_ctx *ctx)
{
	assert(is_ta_ctx(ctx));
	return container_of(ctx, struct tee_ta_ctx, ts_ctx);
}
#endif
