/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <tee/tee_fs_rpc.h>

void tee_fs_rpc_cache_clear(struct thread_specific_data *tsd)
{
	if (tsd->rpc_fs_payload) {
		thread_rpc_free_payload(tsd->rpc_fs_payload_cookie,
					tsd->rpc_fs_payload_mobj);
		tsd->rpc_fs_payload = NULL;
		tsd->rpc_fs_payload_cookie = 0;
		tsd->rpc_fs_payload_size = 0;
		tsd->rpc_fs_payload_mobj = NULL;
	}
}

void *tee_fs_rpc_cache_alloc(size_t size, struct mobj **mobj, uint64_t *cookie)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	size_t sz = size;
	uint64_t c = 0;
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

		*mobj = thread_rpc_alloc_payload(sz,  &c);
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
		tsd->rpc_fs_payload_cookie = c;
		tsd->rpc_fs_payload_size = sz;
	} else
		*mobj = tsd->rpc_fs_payload_mobj;

	*cookie = tsd->rpc_fs_payload_cookie;
	return tsd->rpc_fs_payload;
err:
	thread_rpc_free_payload(c, *mobj);
	return NULL;
}
