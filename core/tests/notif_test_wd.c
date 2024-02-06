// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <initcall.h>
#include <kernel/callout.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <kernel/virtualization.h>
#include <types_ext.h>

#define TEST_WD_TIMER_PERIOD_MS	1000

struct wd_data {
	bool pending;
	bool enabled;
	uint16_t guest_id;
	unsigned int timeout_count;
	unsigned int call_count;
	struct callout callout;
};

static struct wd_data default_wd_data;
static unsigned int wd_data_id __nex_bss;

static struct wd_data *get_wd_data(struct guest_partition *prtn)
{
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		assert(prtn);
		return virt_get_guest_spec_data(prtn, wd_data_id);
	}
	return &default_wd_data;
}

static bool test_wd_callback(struct callout *co)
{
	struct wd_data *wd = container_of(co, struct wd_data, callout);

	if (wd->pending)
		wd->timeout_count++;
	wd->call_count++;
	if (wd->call_count < 10 || !(wd->call_count % 60) || wd->pending) {
		if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
			DMSG("WD %"PRIu16" call_count %u, timeout_count %u",
			     wd->guest_id, wd->call_count, wd->timeout_count);
		else
			DMSG("WD call_count %u, timeout_count %u",
			     wd->call_count, wd->timeout_count);
	}
	wd->pending = true;
	notif_send_async(NOTIF_VALUE_DO_BOTTOM_HALF, wd->guest_id);

	return true;
}

static void wd_ndrv_atomic_cb(struct notif_driver *ndrv __unused,
			      enum notif_event ev, uint16_t guest_id)
{
	if (ev == NOTIF_EVENT_STARTED) {
		struct guest_partition *prtn = virt_get_guest(guest_id);
		struct wd_data *wd = get_wd_data(prtn);

		if (!wd->enabled) {
			wd->guest_id = guest_id;
			callout_add(&wd->callout, test_wd_callback,
				    TEST_WD_TIMER_PERIOD_MS);

			wd->enabled = true;
		}
		virt_put_guest(prtn);
	}
}
DECLARE_KEEP_PAGER(wd_ndrv_atomic_cb);

static void wd_ndrv_yielding_cb(struct notif_driver *ndrv __unused,
				enum notif_event ev)
{
	if (ev == NOTIF_EVENT_DO_BOTTOM_HALF) {
		struct guest_partition *prtn = virt_get_current_guest();
		struct wd_data *wd = get_wd_data(prtn);

		if (wd->pending && wd->call_count < 10)
			DMSG("Clearing pending");
		wd->pending = false;
		virt_put_guest(prtn);
	}
}

struct notif_driver wd_ndrv __nex_data = {
	.atomic_cb = wd_ndrv_atomic_cb,
	.yielding_cb = wd_ndrv_yielding_cb,
};

static void wd_data_destroy(void *data)
{
	struct wd_data *wd = data;

	callout_rem(&wd->callout);
}

static TEE_Result nex_init_test_wd(void)
{
	TEE_Result res = TEE_SUCCESS;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		res = virt_add_guest_spec_data(&wd_data_id,
					       sizeof(struct wd_data),
					       wd_data_destroy);
		if (res)
			return res;
	}

	notif_register_driver(&wd_ndrv);

	return TEE_SUCCESS;
}

nex_early_init(nex_init_test_wd);

struct periodic_data {
	unsigned int count;
	struct callout callout;
};

static bool periodic_callback(struct callout *co)
{
	struct periodic_data *d = container_of(co, struct periodic_data,
					       callout);
	TEE_Time t = { };

	if (tee_time_get_sys_time(&t))
		panic();
	d->count++;
	DMSG("seconds %"PRIu32" millis %"PRIu32" count %u",
	     t.seconds, t.millis, d->count);

	if (d->count > 20) {
		DMSG("Disabling periodic callout");
		return false;
	}

	return true;
}
DECLARE_KEEP_PAGER(periodic_callback);

static TEE_Result nex_init_periodic_callback(void)
{
	struct periodic_data *d = nex_calloc(1, sizeof(*d));

	if (!d)
		return TEE_ERROR_OUT_OF_MEMORY;

	DMSG("Adding a periodic callout");
	callout_add(&d->callout, periodic_callback, TEST_WD_TIMER_PERIOD_MS);

	return TEE_SUCCESS;
}

nex_early_init(nex_init_periodic_callback);
