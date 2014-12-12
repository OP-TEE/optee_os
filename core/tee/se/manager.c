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
#include <kernel/tee_common_unpg.h>
#include <kernel/mutex.h>
#include <tee/se/manager.h>
#include <tee/se/session.h>
#include <tee/se/reader.h>
#include <tee/se/reader/interface.h>

#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

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

TEE_Result tee_se_reader_check_state(struct tee_se_reader_proxy *proxy)
{
	struct tee_se_reader *r;

	if (proxy->refcnt == 0)
		return TEE_ERROR_BAD_STATE;

	r = proxy->reader;
	if (r->ops->get_state) {
		enum tee_se_reader_state state;

		mutex_lock(&proxy->mutex);
		state = r->ops->get_state(r);
		mutex_unlock(&proxy->mutex);

		if (state != READER_STATE_SE_INSERTED)
			return TEE_ERROR_COMMUNICATION;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_se_reader_get_name(struct tee_se_reader_proxy *proxy,
		char **reader_name, size_t *reader_name_len)
{
	size_t name_len;

	TEE_ASSERT(proxy != NULL && proxy->reader != NULL);

	name_len = strlen(proxy->reader->name);
	*reader_name = proxy->reader->name;
	*reader_name_len = name_len;

	return TEE_SUCCESS;
}

void tee_se_reader_get_properties(struct tee_se_reader_proxy *proxy,
		TEE_SEReaderProperties *prop)
{
	TEE_ASSERT(proxy != NULL && proxy->reader != NULL);
	*prop = proxy->reader->prop;
}

int tee_se_reader_get_refcnt(struct tee_se_reader_proxy *proxy)
{
	TEE_ASSERT(proxy != NULL && proxy->reader != NULL);
	return proxy->refcnt;
}

TEE_Result tee_se_reader_attach(struct tee_se_reader_proxy *proxy)
{
	TEE_Result ret;

	mutex_lock(&proxy->mutex);
	if (proxy->refcnt == 0) {
		struct tee_se_reader *r = proxy->reader;

		if (r->ops->open) {
			ret = r->ops->open(r);
			if (ret != TEE_SUCCESS) {
				mutex_unlock(&proxy->mutex);
				return ret;
			}
		}
	}
	proxy->refcnt++;
	mutex_unlock(&proxy->mutex);
	return TEE_SUCCESS;
}

void tee_se_reader_detach(struct tee_se_reader_proxy *proxy)
{
	TEE_ASSERT(proxy->refcnt > 0);

	mutex_lock(&proxy->mutex);
	proxy->refcnt--;
	if (proxy->refcnt == 0) {
		struct tee_se_reader *r = proxy->reader;

		if (r->ops->close)
			r->ops->close(r);
	}
	mutex_unlock(&proxy->mutex);

}

TEE_Result tee_se_reader_transmit(struct tee_se_reader_proxy *proxy,
		uint8_t *tx_buf, size_t tx_buf_len,
		uint8_t *rx_buf, size_t *rx_buf_len)
{
	struct tee_se_reader *r;
	TEE_Result ret;

	TEE_ASSERT(proxy != NULL && proxy->reader != NULL);
	ret = tee_se_reader_check_state(proxy);
	if (ret != TEE_SUCCESS)
		return ret;

	mutex_lock(&proxy->mutex);
	r = proxy->reader;

	TEE_ASSERT(r->ops->transmit);
	ret = r->ops->transmit(r, tx_buf, tx_buf_len, rx_buf, rx_buf_len);

	mutex_unlock(&proxy->mutex);

	return ret;
}

void tee_se_reader_lock_basic_channel(struct tee_se_reader_proxy *proxy)
{
	TEE_ASSERT(proxy != NULL);

	mutex_lock(&proxy->mutex);
	proxy->basic_channel_locked = true;
	mutex_unlock(&proxy->mutex);
}

void tee_se_reader_unlock_basic_channel(struct tee_se_reader_proxy *proxy)
{
	TEE_ASSERT(proxy != NULL);

	mutex_lock(&proxy->mutex);
	proxy->basic_channel_locked = false;
	mutex_unlock(&proxy->mutex);
}

bool tee_se_reader_is_basic_channel_locked(struct tee_se_reader_proxy *proxy)
{
	TEE_ASSERT(proxy != NULL);
	return proxy->basic_channel_locked;
}

bool tee_se_reader_is_proxy_valid(struct tee_se_reader_proxy *proxy)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_proxy *h;

	TAILQ_FOREACH(h, &ctx->reader_proxies, link) {
		if (h == proxy)
			return true;
	}

	return false;
}

TEE_Result tee_se_reader_get_atr(struct tee_se_reader_proxy *proxy,
		uint8_t **atr, size_t *atr_len)
{
	TEE_Result ret;
	struct tee_se_reader *r;

	TEE_ASSERT(proxy != NULL && atr != NULL && atr_len != NULL);
	ret = tee_se_reader_check_state(proxy);
	if (ret != TEE_SUCCESS)
		return ret;

	mutex_lock(&proxy->mutex);
	r = proxy->reader;

	TEE_ASSERT(r->ops->get_atr);
	ret = r->ops->get_atr(r, atr, atr_len);

	mutex_unlock(&proxy->mutex);
	return ret;
}

TEE_Result tee_se_reader_open_session(struct tee_se_reader_proxy *proxy,
		struct tee_se_session **session)
{
	TEE_Result ret;
	struct tee_se_session *s;

	TEE_ASSERT(session != NULL && *session == NULL);
	TEE_ASSERT(proxy != NULL && proxy->reader != NULL);

	s = tee_se_session_alloc(proxy);
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = tee_se_reader_attach(proxy);
	if (ret != TEE_SUCCESS)
		goto err_free_session;

	*session = s;

	return TEE_SUCCESS;
err_free_session:
	tee_se_session_free(s);
	return ret;
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
