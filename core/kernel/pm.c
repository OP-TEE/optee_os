// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <keep.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <types_ext.h>

#define PM_FLAG_SUSPENDED	BIT(0)

static struct pm_callback_handle *pm_cb_ref;
static size_t pm_cb_count;

static void verify_cb_args(struct pm_callback_handle *pm_hdl)
{
	if (is_unpaged((void *)(vaddr_t)pm_change_state) &&
	    (!is_unpaged((void *)(vaddr_t)pm_hdl->callback) ||
	     (pm_hdl->handle && !is_unpaged(pm_hdl->handle)))) {
		EMSG("PM callbacks mandates unpaged arguments: %p %p",
		     (void *)(vaddr_t)pm_hdl->callback, pm_hdl->handle);
		panic();
	}
}

void register_pm_cb(struct pm_callback_handle *pm_hdl)
{
	size_t count = pm_cb_count;
	struct pm_callback_handle *ref;

	verify_cb_args(pm_hdl);

	ref = realloc(pm_cb_ref, sizeof(*ref) * (count + 1));
	if (!ref)
		panic();

	ref[count] = *pm_hdl;
	ref[count].flags = 0;

	pm_cb_count = count + 1;
	pm_cb_ref = ref;
}

static TEE_Result call_callbacks(enum pm_op op, uint32_t pm_hint,
				 enum pm_callback_order order)
{
	struct pm_callback_handle *hdl;
	size_t n;
	TEE_Result res;

	for (n = 0, hdl = pm_cb_ref; n < pm_cb_count; n++, hdl++) {
		if (hdl->order != order ||
		    (hdl->flags & PM_FLAG_SUSPENDED) == (op == PM_OP_SUSPEND))
			continue;

		res = hdl->callback(op, pm_hint, hdl);
		if (res)
			return res;

		if (op == PM_OP_SUSPEND)
			hdl->flags |= PM_FLAG_SUSPENDED;
		else
			hdl->flags &= ~PM_FLAG_SUSPENDED;
	}

	return TEE_SUCCESS;
}

TEE_Result pm_change_state(enum pm_op op, uint32_t pm_hint)
{
	enum pm_callback_order cnt;
	TEE_Result res;

	switch (op) {
	case PM_OP_SUSPEND:
		for (cnt = PM_CB_ORDER_DRIVER; cnt < PM_CB_ORDER_MAX; cnt++) {
			res = call_callbacks(op, pm_hint, cnt);
			if (res)
				return res;
		}
		break;
	case PM_OP_RESUME:
		for (cnt = PM_CB_ORDER_MAX; cnt > PM_CB_ORDER_DRIVER; cnt--) {
			res = call_callbacks(op, pm_hint, cnt - 1);
			if (res)
				return res;
		}
		break;
	default:
		panic();
	}

	return TEE_SUCCESS;
}
