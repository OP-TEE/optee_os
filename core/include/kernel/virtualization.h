/*
 * Copyright (c) 2017, EPAM Systems
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

#ifndef KERNEL_VIRTUALIZATION_H
#define KERNEL_VIRTUALIZATION_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <mm/mobj.h>

struct thread_rpc_arg {
	uint64_t rpc_carg;
	void *rpc_arg;
	struct mobj *rpc_mobj;
};

struct client_context {
#ifdef CFG_VIRTUALIZATION
	LIST_ENTRY(client_context) next;
#endif
	struct thread_rpc_arg thr_rpc_arg[CFG_NUM_THREADS];
	bool thread_prealloc_rpc_cache;
	uint16_t id;
};

#ifdef CFG_VIRTUALIZATION

/*
 * Get context of current VM client. Works only in std call
 * context (e.g. after thread was created).
 */
struct client_context *curr_client(void);

/*
 * Get context by @client_id. Should be used in fast calls.
 * It is slower than curr_client();
 */
struct client_context *get_client_context(uint16_t client_id);

/*
 * Makes curr_client() return structure for given client_id.
 * Returns true on success, false on error.
 * In case of error, curr_client() will return NULL
 */
bool update_curr_client(uint16_t client_id);

int client_created(uint16_t client_id);
void client_destroyed(uint16_t client_id);

#else

extern struct client_context default_ctx;

static inline struct client_context *curr_client(void)
{
	return &default_ctx;
}

static inline struct client_context *
		get_client_context(uint16_t client_id __unused)
{
	return &default_ctx;
}

static inline bool update_curr_client(uint16_t client_id __unused)
{
	return true;
}

#endif	/* CFG_VIRTUALIZATION */

#endif	/* KERNEL_VIRTUALIZATION_H */
