// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <tee/tee_fs_rpc.h>

void tee_fs_rpc_cache_clear(struct thread_specific_data *tsd)
{
	if (tsd->rpc_fs_payload) {
		thread_rpc_free_payload(tsd->rpc_fs_payload_mobj);
		tsd->rpc_fs_payload = NULL;
		tsd->rpc_fs_payload_size = 0;
		tsd->rpc_fs_payload_mobj = NULL;
	}
}

void *tee_fs_rpc_cache_alloc(size_t size, struct mobj **mobj)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	size_t sz = size;
	paddr_t p;
	void *va;

	if (!size)
		return NULL;

	/*
	 * Always allocate in page chunks as normal world allocates payload
	 * memory as complete pages.
	 */
	sz = ROUNDUP(size, SMALL_PAGE_SIZE);

	if (sz > tsd->rpc_fs_payload_size) {
		tee_fs_rpc_cache_clear(tsd);

		*mobj = thread_rpc_alloc_payload(sz);
		if (!*mobj)
			return NULL;

		if (mobj_get_pa(*mobj, 0, 0, &p))
			goto err;

		if (!ALIGNMENT_IS_OK(p, uint64_t))
			goto err;

		va = mobj_get_va(*mobj, 0);
		if (!va)
			goto err;

		tsd->rpc_fs_payload = va;
		tsd->rpc_fs_payload_mobj = *mobj;
		tsd->rpc_fs_payload_size = sz;
	} else
		*mobj = tsd->rpc_fs_payload_mobj;

	return tsd->rpc_fs_payload;
err:
	thread_rpc_free_payload(*mobj);
	return NULL;
}
