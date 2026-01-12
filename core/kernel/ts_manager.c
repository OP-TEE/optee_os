// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */

#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/ts_manager.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_mmu.h>
#include <mm/vm.h>

static void update_current_ctx(struct thread_specific_data *tsd)
{
	struct ts_ctx *ctx = NULL;
	struct ts_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		if (is_pseudo_ta_ctx(s->ctx))
			s = TAILQ_NEXT(s, link_tsd);

		if (s)
			ctx = s->ctx;
	}

	if (tsd->ctx != ctx)
		vm_set_ctx(ctx);
	/*
	 * If current context is of user mode, then it has to be active too.
	 */
	if (is_user_mode_ctx(ctx) != core_mmu_user_mapping_is_active())
		panic("unexpected active mapping");
}

static void *swap_fbuf(struct ts_session *s __maybe_unused,
		       void *fbuf __maybe_unused)
{
	void *ret = NULL;

#if defined(CFG_FTRACE_SUPPORT)
	ret = s->fbuf;
	s->fbuf = fbuf;
#endif

	return ret;
}

void ts_push_current_session(struct ts_session *s)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	uint32_t state = 0;
	void *fbuf = NULL;

	/*
	 * If ftrace is enabled we may access the session list and the fbuf
	 * field in the current (first) session when processing a foreign
	 * interrupt when saving the state of the thread. Mask foreign
	 * interrupts temporarily to make sure that we present a consistent
	 * state.
	 *
	 * We disable the fbuf temporarily while switching mapped TS to
	 * since this isn't an atomic operation, that is, the mappings are
	 * replaced entry by entry so it's not clear what is mapped during
	 * the call to update_current_ctx().
	 */

	if (IS_ENABLED(CFG_FTRACE_SUPPORT)) {
		state = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
		fbuf = swap_fbuf(s, NULL);
	}

	TAILQ_INSERT_HEAD(&tsd->sess_stack, s, link_tsd);

	if (IS_ENABLED(CFG_FTRACE_SUPPORT))
		thread_unmask_exceptions(state);

	update_current_ctx(tsd);

	if (IS_ENABLED(CFG_FTRACE_SUPPORT) && fbuf) {
		state = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
		swap_fbuf(s, fbuf);
		thread_unmask_exceptions(state);
	}
}

struct ts_session *ts_pop_current_session(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct ts_session *s = TAILQ_FIRST(&tsd->sess_stack);
	struct ts_session *s2 = NULL;
	uint32_t state = 0;
	void *fbuf = NULL;

	if (!s)
		return NULL;

	/* See comment in ts_push_current_session() above for ftrace support */

	if (IS_ENABLED(CFG_FTRACE_SUPPORT)) {
		s2 = TAILQ_NEXT(s, link_tsd);
		if (s2)
			fbuf = swap_fbuf(s2, NULL);
		state = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	}

	TAILQ_REMOVE(&tsd->sess_stack, s, link_tsd);

	if (IS_ENABLED(CFG_FTRACE_SUPPORT))
		thread_unmask_exceptions(state);

	update_current_ctx(tsd);

	if (IS_ENABLED(CFG_FTRACE_SUPPORT) && fbuf) {
		state = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
		swap_fbuf(s2, fbuf);
		thread_unmask_exceptions(state);
	}

	return s;
}

struct ts_session *ts_get_calling_session(void)
{
	return TAILQ_NEXT(ts_get_current_session(), link_tsd);
}

struct ts_session *ts_get_current_session_may_fail(void)
{
	return TAILQ_FIRST(&thread_get_tsd()->sess_stack);
}

struct ts_session *ts_get_current_session(void)
{
	struct ts_session *s = ts_get_current_session_may_fail();

	if (!s)
		panic();
	return s;
}
