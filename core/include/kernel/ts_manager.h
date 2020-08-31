/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef __KERNEL_TS_MANAGER_H
#define __KERNEL_TS_MANAGER_H

#include <sys/queue.h>

struct ts_session {
	TAILQ_ENTRY(ts_session) link_tsd;
	struct tee_ta_ctx *ctx;	/* TA context */
#if defined(CFG_TA_GPROF_SUPPORT)
	struct sample_buf *sbuf; /* Profiling data (PC sampling) */
#endif
#if defined(CFG_FTRACE_SUPPORT)
	struct ftrace_buf *fbuf; /* ftrace buffer */
#endif
};

struct ts_session *ts_get_current_session(void);
struct ts_session *ts_get_current_session_may_fail(void);

void ts_push_current_session(struct ts_session *sess);
struct ts_session *ts_pop_current_session(void);
struct ts_session *ts_get_calling_session(void);

#endif /*__KERNEL_TS_MANAGER_H*/
