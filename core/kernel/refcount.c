// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <assert.h>
#include <atomic.h>
#include <kernel/refcount.h>

bool refcount_inc(struct refcount *r)
{
	unsigned int nval;
	unsigned int oval = atomic_load_uint(&r->val);

	while (true) {
		nval = oval + 1;

		/* r->val is 0, we can't do anything more. */
		if (!oval)
			return false;

		if (atomic_cas_uint(&r->val, &oval, nval))
			return true;
		/*
		 * At this point atomic_cas_uint() has updated oval to the
		 * current r->val.
		 */
	}
}

bool refcount_dec(struct refcount *r)
{
	unsigned int nval;
	unsigned int oval = atomic_load_uint(&r->val);

	while (true) {
		assert(oval);
		nval = oval - 1;

		if (atomic_cas_uint(&r->val, &oval, nval)) {
			/*
			 * Value has been updated, if value was set to 0
			 * return true to indicate that.
			 */
			return !nval;
		}
		/*
		 * At this point atomic_cas_uint() has updated oval to the
		 * current r->val.
		 */
	}
}
