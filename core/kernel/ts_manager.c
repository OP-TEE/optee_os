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

void ts_push_current_session(struct ts_session *s)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	TAILQ_INSERT_HEAD(&tsd->sess_stack, s, link_tsd);
	update_current_ctx(tsd);
}

struct ts_session *ts_pop_current_session(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct ts_session *s = TAILQ_FIRST(&tsd->sess_stack);

	if (s) {
		TAILQ_REMOVE(&tsd->sess_stack, s, link_tsd);
		update_current_ctx(tsd);
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
