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

#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/virtualization.h>
#include <kernel/thread.h>
#include <sm/optee_smc.h>
#include <sys/queue.h>
#include <string.h>

#ifdef CFG_VIRTUALIZATION

static unsigned int ctx_list_lock = SPINLOCK_UNLOCK;

static LIST_HEAD(ctx_list_head, client_context) ctx_list =
	LIST_HEAD_INITIALIZER(ctx_list_head);

struct client_context *curr_client(void)
{
	return thread_get_tsd()->client_ctx;
}

struct client_context *get_client_context(uint16_t client_id)
{
	struct client_context *ctx;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&ctx_list_lock);
	LIST_FOREACH(ctx, &ctx_list, next) {
		if (ctx->id == client_id) {
			cpu_spin_unlock_xrestore(&ctx_list_lock,
						 exceptions);
			return ctx;
		}
	}
	cpu_spin_unlock_xrestore(&ctx_list_lock, exceptions);

	return NULL;
}

bool update_curr_client(uint16_t client_id)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct client_context *ctx = get_client_context(client_id);

	if (!ctx)
		EMSG("Can't find VM client with id %d", client_id);

	tsd->client_ctx = ctx;

	return ctx != NULL;
}

int client_created(uint16_t client_id)
{
	struct client_context *ctx;
	uint32_t exceptions;

	ctx = malloc(sizeof(*ctx));

	if (!ctx)
		return OPTEE_SMC_RETURN_ENOTAVAIL;

	memset(ctx, 0, sizeof(*ctx));

	ctx->id = client_id;

	exceptions = cpu_spin_lock_xsave(&ctx_list_lock);
	LIST_INSERT_HEAD(&ctx_list, ctx, next);
	cpu_spin_unlock_xrestore(&ctx_list_lock, exceptions);

	DMSG("Added client %d", client_id);

	return OPTEE_SMC_RETURN_OK;
}

void client_destroyed(uint16_t client_id)
{
	struct client_context *ctx;
	uint32_t exceptions;

	DMSG("Removing client %d", client_id);

	exceptions = cpu_spin_lock_xsave(&ctx_list_lock);
	LIST_FOREACH(ctx, &ctx_list, next) {
		if (ctx->id == client_id) {
			LIST_REMOVE(ctx, next);
			break;
		}
	}
	cpu_spin_unlock_xrestore(&ctx_list_lock, exceptions);

	if (!ctx) {
		EMSG("client_destroyed: can't find cliend with id %d",
		     client_id);
		return;
	}

	/* Now we have pointer to client context and can perform cleanup */

	/* This should be last step. At this point all client threads
	 * should be stopped.
	 * TODO: Implement thread termination.
	 */
	thread_force_free_prealloc_rpc_cache(ctx);
}

static TEE_Result virtualization_init(void)
{
	/* Create context for hypervisor manually */
	int ret = client_created(0);

	if (ret)
		panic("Can't create hypervisor client context");

	return TEE_SUCCESS;
}

service_init(virtualization_init);

#else

struct client_context default_ctx;

#endif	/* CFG_VIRTUALIZATION */
