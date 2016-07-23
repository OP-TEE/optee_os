/*
 * Copyright (c) 2014, Linaro Limited
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
#include <trace.h>
#include <kernel/mutex.h>
#include <tee/se/manager.h>
#include <tee/se/session.h>
#include <tee/se/reader.h>
#include <tee/se/reader/interface.h>

#include <stdlib.h>
#include <sys/queue.h>

#include "reader_priv.h"
#include "session_priv.h"

TAILQ_HEAD(reader_proxy_head, tee_se_reader_proxy);

struct tee_se_manager_ctx {
	/* number of readers registered */
	size_t reader_count;
	/* mutex to pretect the reader proxy list */
	struct mutex mutex;
	/* list of registered readers */
	struct reader_proxy_head reader_proxies;
};
static struct tee_se_manager_ctx se_manager_ctx;

TEE_Result tee_se_manager_register_reader(struct tee_se_reader *r)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_proxy *proxy =
		malloc(sizeof(struct tee_se_reader_proxy));
	if (!proxy)
		return TEE_ERROR_OUT_OF_MEMORY;

	proxy->reader = r;
	proxy->refcnt = 0;
	proxy->basic_channel_locked = false;
	mutex_init(&proxy->mutex);

	mutex_lock(&ctx->mutex);
	TAILQ_INSERT_TAIL(&ctx->reader_proxies, proxy, link);
	ctx->reader_count++;
	mutex_unlock(&ctx->mutex);

	return TEE_SUCCESS;
}

TEE_Result tee_se_manager_unregister_reader(struct tee_se_reader *r)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_proxy *proxy;

	mutex_lock(&ctx->mutex);
	TAILQ_FOREACH(proxy, &ctx->reader_proxies, link)
	{
		if (proxy->reader == r)
			TAILQ_REMOVE(&ctx->reader_proxies, proxy, link);
		free(proxy);
	}
	ctx->reader_count--;
	mutex_unlock(&ctx->mutex);

	return TEE_SUCCESS;
}

size_t tee_se_manager_get_reader_count(void)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;

	return ctx->reader_count;
}

TEE_Result tee_se_manager_get_readers(
		struct tee_se_reader_proxy **proxy_list,
		size_t *proxy_list_size)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_proxy *proxy;
	size_t i = 0;

	if (TAILQ_EMPTY(&ctx->reader_proxies))
		return TEE_ERROR_ITEM_NOT_FOUND;

	TAILQ_FOREACH(proxy, &ctx->reader_proxies, link) {
		if (i >= *proxy_list_size)
			return TEE_ERROR_SHORT_BUFFER;

		proxy_list[i] = proxy;
		i++;
	}
	*proxy_list_size = i;

	return TEE_SUCCESS;
}

bool tee_se_manager_is_reader_proxy_valid(
		struct tee_se_reader_proxy *proxy)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_proxy *h;

	TAILQ_FOREACH(h, &ctx->reader_proxies, link) {
		if (h == proxy)
			return true;
	}

	return false;
}

static void context_init(struct tee_se_manager_ctx *ctx)
{
	TAILQ_INIT(&ctx->reader_proxies);
	mutex_init(&ctx->mutex);
	ctx->reader_count = 0;
}

static TEE_Result tee_se_manager_init(void)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;

	context_init(ctx);

	return TEE_SUCCESS;
}

service_init(tee_se_manager_init);
