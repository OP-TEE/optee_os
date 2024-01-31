/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */

#ifndef __KERNEL_CALLOUT_H
#define __KERNEL_CALLOUT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

/*
 * struct callout - callout reference
 * @callback:	  function to be called when a callout expires
 * @expiry_value: callout expiry time counter value
 * @period:	  ticks to next timeout
 * @link:	  linked list element
 *
 * @callback is called from an interrupt handler so thread resources must
 * not be used. The main callout service lock is held while @callback is
 * called so callout_rem() and callout_add() can't be used, but it is safe
 * to call callout_set_next_timeout() if the call period should be changed.
 * @callback returns true if it should be called again in @period ticks
 * or false if the callout should be removed and inactivated. Returning
 * false from @callback is the equivalent of calling callout_rem() on the
 * callout reference.
 */
struct callout {
	bool (*callback)(struct callout *co);
	uint64_t expiry_value;
	uint64_t period;
	TAILQ_ENTRY(callout) link;
};

/*
 * callout_add() - Add a callout
 * @co:		callout reference
 * @callback:	callback function accociated with the callout
 * @ms:		time to next callout in milliseconds
 *
 * Adds a callout to the callout service with an associated callback
 * function @callback that is to be called in @ms milliseconds.
 *
 * If callout_add() is called before callout_service_init() has been called
 * then it will be called @ms milliseconds after callout_service_init() has
 * been called.
 *
 * The callout structure can reside in global data or on the heap. It's
 * safe to embed it inside another struct, but it must not be freed until
 * removed with callout_rem() or equivalent.
 *
 * The function takes the main callout service for synchronization so it
 * can't be called from within a callback function in a callout or there's
 * deadlock.
 */
void callout_add(struct callout *co, bool (*callback)(struct callout *co),
		 uint32_t ms);

/*
 * callout_rem() - Remove a callout
 * @co:		callout reference
 *
 * Removes a callout previously added to the callout service with
 * callout_add(). Note that when the callback function in a callout
 * returns false the callout is also removed.
 *
 * It's safe to try to remove a callback even if it isn't active any
 * longer. Nothing will happen in that case, but it's guaranteed to be
 * inactive and it's safe to free the memory after callout_rem() has
 * returned.
 */
void callout_rem(struct callout *co);

/*
 * callout_set_next_timeout() - set time to next callout
 * @co:		callout reference
 * @ms:		time to next callout in milliseconds
 *
 * Updates the @co->ticks field with the new number of ticks based on @ms.
 * This value is used to when to calculate the time of the next callout
 * following then one already set.
 *
 * Must only be called from @co->callback() when the callout is triggered.
 */
void callout_set_next_timeout(struct callout *co, uint32_t ms);

/*
 * struct callout_timer_desc - callout timer descriptor
 * @disable_timeout:	disables the timer from triggering an interrupt
 * @set_next_timeout:	sets the next timeout and enables the timer
 * @ms_to_ticks:	converts milliseconds to ticks, the counter value
 *			unit
 * @get_now:		get the current counter value
 * @is_per_cpu:		flag to indicate if this timer is per CPU (true) or
 *			global (false).
 *
 * This descriptor provides an abstract timer interface first used by
 * callout_service_init() and then stored to be used by
 * callout_service_cb().
 *
 * When @is_per_cpu is true there is one private timer per CPU so
 * @disable_timeout() and @set_next_timeout() only affects the timer on the
 * current CPU. If for instance @set_next_timeout() is called on a new CPU
 * compared to last time the timer on the old CPU will remain unchanged.
 * Timer interrupts may trigger based on obsolete configuration, the
 * callout service is expected to handle this gracefully.
 */
struct callout_timer_desc {
	void (*disable_timeout)(const struct callout_timer_desc *desc);
	void (*set_next_timeout)(const struct callout_timer_desc *desc,
				 uint64_t expiry_value);
	uint64_t (*ms_to_ticks)(const struct callout_timer_desc *desc,
				uint32_t ms);
	uint64_t (*get_now)(const struct callout_timer_desc *desc);
	bool is_per_cpu;
};

/*
 * callout_service_init() - Initialize the callout service
 * @desc:	Pointer to the timer interface
 *
 * The callout service is initialized with the supplied timer interface
 */
void callout_service_init(const struct callout_timer_desc *desc);

/*
 * callout_service_cb() - Callout service callback
 *
 * Called from interrupt service function for the timer.
 */
void callout_service_cb(void);

#endif /*__KERNEL_CALLOUT_H*/
