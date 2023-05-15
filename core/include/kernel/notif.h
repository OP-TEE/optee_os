/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#ifndef __KERNEL_NOTIF_H
#define __KERNEL_NOTIF_H

#include <compiler.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <config.h>

/*
 * Notification values are divided into two kinds, asynchronous and
 * synchronous, where the asynchronous has the lowest values.
 * They are ordered as:
 * 0			    Do bottom half
 * 1..NOTIF_ASYNC_MAX	    Free for signalling in PTAs and should be
 *			    allocated with notif_alloc_async_value()
 * NOTIF_SYNC_VALUE_BASE..  Used as NOTIF_SYNC_VALUE_BASE + thread_id
 * NOTIF_VALUE_MAX	    for mutex and condvar wait/wakeup
 *
 * Any value can be signalled with notif_send_sync() while only the ones
 * <= NOTIF_ASYNC_VALUE_MAX can be signalled with notif_send_async().
 */

#if defined(CFG_CORE_ASYNC_NOTIF)
#define NOTIF_ASYNC_VALUE_MAX		U(63)
#define NOTIF_SYNC_VALUE_BASE		(NOTIF_ASYNC_VALUE_MAX + U(1))
#else
#define NOTIF_SYNC_VALUE_BASE		0
#endif

#define NOTIF_VALUE_MAX			(NOTIF_SYNC_VALUE_BASE + \
					 CFG_NUM_THREADS)

#define NOTIF_VALUE_DO_BOTTOM_HALF	0

/*
 * enum notif_event - Notification of an event
 * @NOTIF_EVENT_STARTED:	Delivered in an atomic context to inform
 *				drivers that normal world has enabled
 *				asynchronous notifications.
 * @NOTIF_EVENT_DO_BOTTOM_HALF: Delivered in a yielding context to let a
 *				driver do bottom half processing.
 * @NOTIF_EVENT_STOPPED:	Delivered in a yielding contest to inform
 *				drivers that normal world is about to disable
 *				asynchronous notifications.
 *
 * Once a driver has received a @NOTIF_EVENT_STARTED asynchronous notifications
 * driving the @NOTIF_EVENT_DO_BOTTOM_HALF deliveries is enabled.
 *
 * In case a @NOTIF_EVENT_STOPPED is received there will be no more
 * @NOTIF_EVENT_DO_BOTTOM_HALF events delivered, until @NOTIF_EVENT_STARTED
 * has been delivered again.
 *
 * Note that while a @NOTIF_EVENT_STOPPED is being delivered at the same
 * time may a @NOTIF_EVENT_STARTED be delivered again so a driver is
 * required to sychronize accesses to its internal state.
 */
enum notif_event {
	NOTIF_EVENT_STARTED,
	NOTIF_EVENT_DO_BOTTOM_HALF,
	NOTIF_EVENT_STOPPED,
};

/*
 * struct notif_driver - Registration of driver notification
 * @atomic_cb:	 A callback called in an atomic context from
 *		 notif_deliver_atomic_event(). Currently only used to
 *		 signal @NOTIF_EVENT_STARTED.
 * @yielding_cb: A callback called in a yielding context from
 *		 notif_deliver_event(). Currently only used to signal
 *		 @NOTIF_EVENT_DO_BOTTOM_HALF and @NOTIF_EVENT_STOPPED.
 *
 * A atomic context means that interrupts are masked and a common spinlock
 * is held. Calls via @atomic_cb are only atomic with regards to each
 * other, other CPUs may execute yielding calls or even receive interrupts.
 *
 * A yielding context means that the function is executing in a normal
 * threaded context allowing RPC and synchronization with other thread
 * using mutexes and condition variables.
 */
struct notif_driver {
	void (*atomic_cb)(struct notif_driver *ndrv, enum notif_event ev);
	void (*yielding_cb)(struct notif_driver *ndrv, enum notif_event ev);
	SLIST_ENTRY(notif_driver) link;
};

#if defined(CFG_CORE_ASYNC_NOTIF)
bool notif_async_is_started(void);
#else
static inline bool notif_async_is_started(void)
{
	return false;
}
#endif

TEE_Result notif_alloc_async_value(uint32_t *value);
void notif_free_async_value(uint32_t value);

/*
 * Wait in normal world for a value to be sent by notif_send()
 */
TEE_Result notif_wait(uint32_t value);

/*
 * Send an asynchronous value, note that it must be <= NOTIF_ASYNC_VALUE_MAX
 */
#if defined(CFG_CORE_ASYNC_NOTIF)
void notif_send_async(uint32_t value);
#else
static inline void notif_send_async(uint32_t value __unused)
{
}
#endif

/*
 * Send a sychronous value, note that it must be <= NOTIF_VALUE_MAX. The
 * notification is synchronous even if the value happens to belong in the
 * asynchronous range.
 */
TEE_Result notif_send_sync(uint32_t value);

/*
 * Called by device drivers.
 */
#if defined(CFG_CORE_ASYNC_NOTIF)
void notif_register_driver(struct notif_driver *ndrv);
void notif_unregister_driver(struct notif_driver *ndrv);
#else
static inline void notif_register_driver(struct notif_driver *ndrv __unused)
{
}

static inline void notif_unregister_driver(struct notif_driver *ndrv __unused)
{
}
#endif

/* This is called from a fast call */
#if defined(CFG_CORE_ASYNC_NOTIF)
uint32_t notif_get_value(bool *value_valid, bool *value_pending);
#else
static inline uint32_t notif_get_value(bool *value_valid, bool *value_pending)
{
	*value_valid = false;
	*value_pending = false;
	return UINT32_MAX;
}
#endif

/*
 * These are called from yielding calls
 */
#if defined(CFG_CORE_ASYNC_NOTIF)
void notif_deliver_atomic_event(enum notif_event ev);
void notif_deliver_event(enum notif_event ev);
#else
static inline void notif_deliver_atomic_event(enum notif_event ev __unused)
{
}

static inline void notif_deliver_event(enum notif_event ev __unused)
{
}
#endif

#endif /*__KERNEL_NOTIF_H*/
