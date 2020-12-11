/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017-2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#ifndef __KERNEL_TS_MANAGER_H
#define __KERNEL_TS_MANAGER_H

#include <sys/queue.h>
#include <tee_api_types.h>

struct ts_ctx {
	TEE_UUID uuid;
	const struct ts_ops *ops;
};

struct thread_svc_regs;
struct ts_session {
	TAILQ_ENTRY(ts_session) link_tsd;
	struct ts_ctx *ctx;	/* Generic TS context */
#if defined(CFG_TA_GPROF_SUPPORT)
	struct sample_buf *sbuf; /* Profiling data (PC sampling) */
#endif
#if defined(CFG_FTRACE_SUPPORT)
	struct ftrace_buf *fbuf; /* ftrace buffer */
#endif
	/*
	 * Used by PTAs to store session specific information, or used by ldelf
	 * syscalls to store handlers of opened TA/SP binaries.
	 */
	void *user_ctx;
	bool (*handle_svc)(struct thread_svc_regs *regs);
};

enum ts_gprof_status {
	TS_GPROF_SUSPEND,
	TS_GPROF_RESUME,
};

struct ts_ops {
	TEE_Result (*enter_open_session)(struct ts_session *s);
	TEE_Result (*enter_invoke_cmd)(struct ts_session *s, uint32_t cmd);
	void (*enter_close_session)(struct ts_session *s);
	void (*dump_state)(struct ts_ctx *ctx);
	void (*dump_ftrace)(struct ts_ctx *ctx);
	void (*destroy)(struct ts_ctx *ctx);
	uint32_t (*get_instance_id)(struct ts_ctx *ctx);
	bool (*handle_svc)(struct thread_svc_regs *regs);
#ifdef CFG_TA_GPROF_SUPPORT
	void (*gprof_set_status)(enum ts_gprof_status status);
#endif
};

struct ts_session *ts_get_current_session(void);
struct ts_session *ts_get_current_session_may_fail(void);

void ts_push_current_session(struct ts_session *sess);
struct ts_session *ts_pop_current_session(void);
struct ts_session *ts_get_calling_session(void);

#endif /*__KERNEL_TS_MANAGER_H*/
