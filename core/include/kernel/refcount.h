/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __KERNEL_REFCOUNT_H
#define __KERNEL_REFCOUNT_H

#include <atomic.h>

/*
 * Reference counter
 *
 * When val is 0, refcount_inc() does not change the value and returns false.
 * Otherwise, it increments the value and returns true.
 *
 * refcount_dec() decrements the value and returns true when the call
 * caused the value to become 0, false otherwise.
 *
 * Since each call to refcount_dec() is supposed to match a call to
 * refcount_inc(), refcount_dec() called for val == 0 should never happen.
 *
 * This behaviour makes this pattern possible:
 * if (!refcount_inc(r)) {
 *	mutex_lock(m);
 *	// Some other thread may have initialized o by now so check that
 *	// we still need to initialize o.
 *	if (!o) {
 *		o = initialize();
 *		refcount_set(r, 1);
 *	}
 *	mutex_unlock(m);
 * }
 *
 * or
 * if (refcount_dec(r)) {
 *	mutex_lock(m);
 *	// Now that we have the mutex o can't be ininialized/uninitialized
 *	// by any other thread, check that the refcount value is still 0
 *	// to guard against the thread above already having reinitialized o
 *	if (!refcount_val(r) && o)
 *		uninitialize(o)
 *	mutex_unlock(m);
 * }
 *
 * where r if the reference counter, o is the object and m the mutex
 * protecting the object.
 */

struct refcount {
	unsigned int val;
};

/* Increases refcount by 1, return true if val > 0 else false */
bool refcount_inc(struct refcount *r);
/* Decreases refcount by 1, return true if val == 0 else false */
bool refcount_dec(struct refcount *r);

static inline void refcount_set(struct refcount *r, unsigned int val)
{
	atomic_store_uint(&r->val, val);
}

static inline unsigned int refcount_val(struct refcount *r)
{
	return atomic_load_uint(&r->val);
}

#endif /*!__KERNEL_REFCOUNT_H*/
