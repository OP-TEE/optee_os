// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <kernel/notif.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <rpmi_tee.h>
#include <trace.h>

#include "optee_rpmi_private.h"

/*
 * RPMI asynchronous notification lifecycle
 *
 *   Current state   Operation                            Next state
 * --------------------------------------------------------------------
 *   NO_BUS          optee_rpmi_signal_bus_setup()        DISABLED
 *   DISABLED        optee_rpmi_enable_async_notif()      ENABLED
 *   ENABLED         notif_rpmi_event(STOPPED)            DISABLED
 *   Any             optee_rpmi_signal_bus_teardown()     NO_BUS
 *
 * notif_send_async() raises the bound signal synchronously only in ENABLED.
 * Other states discard doorbells; producers retain their actual pending work.
 *
 * lifecycle_lock serializes bus changes, enabling and STARTED publication,
 * and the STOP callback. The state lock protects the binding and remains held
 * during a raise, so disabling it waits for an already submitted raise.
 * STARTED callbacks run without the state lock and may send immediately.
 *
 * Both locks mask local interrupts to prevent same-hart lock re-entry.
 * Acquire lifecycle_lock before the state lock; senders take only the latter.
 */

int32_t optee_rpmi_signal_bus_setup(uint32_t sender_id __unused,
				    uint32_t bus_width __unused,
				    uint32_t sender_signals __unused)
{
	struct optee_rpmi_notif_state *state = optee_rpmi_notif_context();
	uint32_t lifecycle_exceptions =
		cpu_spin_lock_xsave(&state->lifecycle_lock);
	uint32_t exceptions = cpu_spin_lock_xsave(&state->lock);
	int32_t status = RPMI_ERR_DENIED;

	/* NO_BUS -> DISABLED. */
	if (state->status == OPTEE_RPMI_NOTIF_NO_BUS) {
		state->status = OPTEE_RPMI_NOTIF_DISABLED;
		status = RPMI_SUCCESS;
	}

	cpu_spin_unlock_xrestore(&state->lock, exceptions);
	cpu_spin_unlock_xrestore(&state->lifecycle_lock, lifecycle_exceptions);

	return status;
}

TEE_Result optee_rpmi_enable_async_notif(uint32_t peer, uint32_t signal)
{
	struct optee_rpmi_notif_state *state = optee_rpmi_notif_context();
	uint32_t lifecycle_exceptions =
		cpu_spin_lock_xsave(&state->lifecycle_lock);
	uint32_t exceptions = cpu_spin_lock_xsave(&state->lock);
	TEE_Result res = TEE_SUCCESS;

	if (state->status == OPTEE_RPMI_NOTIF_NO_BUS) {
		res = TEE_ERROR_ACCESS_DENIED;
		goto out;
	}

	if (state->status == OPTEE_RPMI_NOTIF_ENABLED) {
		res = TEE_ERROR_BUSY;
		goto out;
	}

	/* DISABLED -> ENABLED. */
	state->peer_id = peer;
	state->signal_id = signal;
	state->status = OPTEE_RPMI_NOTIF_ENABLED;

out:
	cpu_spin_unlock_xrestore(&state->lock, exceptions);
	/* STARTED callbacks may send, so release the state lock first. */
	if (!res)
		notif_deliver_atomic_event(NOTIF_EVENT_STARTED, 0);
	cpu_spin_unlock_xrestore(&state->lifecycle_lock, lifecycle_exceptions);

	return res;
}

void notif_send_async(uint32_t value, uint16_t guest_id __unused)
{
	struct optee_rpmi_notif_state *state = optee_rpmi_notif_context();
	uint32_t exceptions = cpu_spin_lock_xsave(&state->lock);
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	assert(value == NOTIF_VALUE_DO_BOTTOM_HALF);

	if (state->status != OPTEE_RPMI_NOTIF_ENABLED)
		goto out;

	res = rpmi_tee_signal_raise(optee_rpmi_channel(), state->peer_id,
				    state->signal_id, &status);
	/* Teardown may reject raises before its request reaches us. */
	if (res || (status != RPMI_SUCCESS && status != RPMI_ERR_DENIED)) {
		EMSG("RPMI signal raise failed: %#" PRIx32, res);
		EMSG("RPMI signal status: %" PRId32, status);
		panic();
	}

out:
	cpu_spin_unlock_xrestore(&state->lock, exceptions);
}

/* Bus teardown is not a yielding service STOP or parcel/call retirement. */
void optee_rpmi_signal_bus_teardown(uint32_t sender_id __unused)
{
	struct optee_rpmi_notif_state *state = optee_rpmi_notif_context();
	uint32_t lifecycle_exceptions =
		cpu_spin_lock_xsave(&state->lifecycle_lock);
	uint32_t exceptions = cpu_spin_lock_xsave(&state->lock);

	/* Any -> NO_BUS. */
	state->status = OPTEE_RPMI_NOTIF_NO_BUS;
	state->peer_id = 0;
	state->signal_id = 0;

	cpu_spin_unlock_xrestore(&state->lock, exceptions);
	cpu_spin_unlock_xrestore(&state->lifecycle_lock, lifecycle_exceptions);
}

/* Atomic events require no backend action. */
static void notif_rpmi_atomic_cb(struct notif_driver *driver __unused,
				 enum notif_event event __unused,
				 uint16_t guest_id __unused)
{
}
DECLARE_KEEP_PAGER(notif_rpmi_atomic_cb);

static void notif_rpmi_event(struct notif_driver *driver __unused,
			     enum notif_event event)
{
	struct optee_rpmi_notif_state *state = optee_rpmi_notif_context();
	uint32_t lifecycle_exceptions = 0;
	uint32_t exceptions = 0;

	if (event != NOTIF_EVENT_STOPPED)
		return;

	lifecycle_exceptions = cpu_spin_lock_xsave(&state->lifecycle_lock);
	/* An older STOPPED callback must not disable a restarted binding. */
	if (!notif_async_is_started(0)) {
		exceptions = cpu_spin_lock_xsave(&state->lock);
		/* ENABLED -> DISABLED. */
		if (state->status == OPTEE_RPMI_NOTIF_ENABLED)
			state->status = OPTEE_RPMI_NOTIF_DISABLED;
		cpu_spin_unlock_xrestore(&state->lock, exceptions);
	}
	cpu_spin_unlock_xrestore(&state->lifecycle_lock, lifecycle_exceptions);
}

void notif_rpmi_init(struct optee_rpmi_notif_state *state)
{
	state->driver.atomic_cb = notif_rpmi_atomic_cb;
	state->driver.yielding_cb = notif_rpmi_event;
	notif_register_driver(&state->driver);
}
