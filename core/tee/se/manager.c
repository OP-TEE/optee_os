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
#include <kernel/tee_ta_manager_unpg.h>
#include <kernel/tee_common_unpg.h>
#include <tee/se/manager.h>
#include <tee/se/session.h>
#include <tee/se/reader/interface.h>

#include <kernel/mutex.h>

#include <tee/se/reader.h>

#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

TAILQ_HEAD(reader_handles_list, tee_se_reader_handle);

struct tee_se_reader_handle {
	struct tee_se_reader *reader;
	uint32_t refcnt;
	bool basic_channel_locked;
	struct mutex mutex;
	TAILQ_ENTRY(tee_se_reader_handle) link;
};

struct tee_se_manager_ctx {

	struct mutex mutex;
	struct reader_handles_list reader_handles;
};
static struct tee_se_manager_ctx se_manager_ctx;

TEE_Result tee_se_manager_register_reader(struct tee_se_reader *r)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_handle *handle =
		malloc(sizeof(struct tee_se_reader_handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	handle->reader = r;
	handle->refcnt = 0;
	handle->basic_channel_locked = false;
	mutex_init(&handle->mutex);

	mutex_lock(&ctx->mutex);
	TAILQ_INSERT_TAIL(&ctx->reader_handles, handle, link);
	mutex_unlock(&ctx->mutex);

	return TEE_SUCCESS;
}

TEE_Result tee_se_manager_unregister_reader(struct tee_se_reader *r)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_handle *handle;

	mutex_lock(&ctx->mutex);
	TAILQ_FOREACH(handle, &ctx->reader_handles, link)
	{
		if (handle->reader == r)
			TAILQ_REMOVE(&ctx->reader_handles, handle, link);
		free(handle);
	}
	mutex_unlock(&ctx->mutex);

	return TEE_SUCCESS;
}


TEE_Result tee_se_manager_get_readers(struct tee_se_reader_handle **handle_list,
		size_t *handle_list_size)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;
	struct tee_se_reader_handle *handle;
	size_t i = 0;

	if (TAILQ_EMPTY(&ctx->reader_handles))
		return TEE_ERROR_ITEM_NOT_FOUND;

	TAILQ_FOREACH(handle, &ctx->reader_handles, link) {
		if (i >= *handle_list_size)
			return TEE_ERROR_SHORT_BUFFER;

		handle_list[i] = handle;
		i++;
	}
	*handle_list_size = i;

	return TEE_SUCCESS;
}

TEE_Result tee_se_reader_get_name(struct tee_se_reader_handle *handle,
		char *reader_name, size_t *reader_name_len)
{
	size_t name_len;

	TEE_ASSERT(handle != NULL && handle->reader != NULL);

	name_len = strlen(handle->reader->name);
	if (name_len > *reader_name_len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(reader_name, handle->reader->name, *reader_name_len);
	*reader_name_len = name_len;

	return TEE_SUCCESS;
}

void tee_se_reader_get_properties(struct tee_se_reader_handle *handle,
		TEE_SEReaderProperties *prop)
{
	TEE_ASSERT(handle != NULL && handle->reader != NULL);
	*prop = handle->reader->prop;
}

int tee_se_reader_get_refcnt(struct tee_se_reader_handle *handle)
{
	TEE_ASSERT(handle != NULL && handle->reader != NULL);
	return handle->refcnt;
}

TEE_Result tee_se_reader_attach(struct tee_se_reader_handle *handle)
{
	TEE_Result ret;

	mutex_lock(&handle->mutex);
	if (handle->refcnt == 0) {
		struct tee_se_reader *r = handle->reader;

		if (r->ops->open) {
			ret = r->ops->open(r);
			if (ret != TEE_SUCCESS) {
				mutex_unlock(&handle->mutex);
				return ret;
			}
		}
	}
	handle->refcnt++;
	mutex_unlock(&handle->mutex);
	return TEE_SUCCESS;
}

void tee_se_reader_detach(struct tee_se_reader_handle *handle)
{
	TEE_ASSERT(handle->refcnt > 0);

	mutex_lock(&handle->mutex);
	handle->refcnt--;
	if (handle->refcnt == 0) {
		struct tee_se_reader *r = handle->reader;

		if (r->ops->close)
			r->ops->close(r);
	}
	mutex_unlock(&handle->mutex);

}

static TEE_Result check_reader_state(struct tee_se_reader_handle *handle)
{
	struct tee_se_reader *r;
	if (handle->refcnt == 0)
		return TEE_ERROR_BAD_STATE;

	r = handle->reader;
	if (r->ops->get_state) {
		enum tee_se_reader_state state;

		mutex_lock(&handle->mutex);
		state = r->ops->get_state(r);
		mutex_unlock(&handle->mutex);

		if (state != READER_STATE_SE_INSERTED)
			return TEE_ERROR_COMMUNICATION;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_se_reader_transmit(struct tee_se_reader_handle *handle,
		uint8_t *tx_buf, size_t tx_buf_len,
		uint8_t *rx_buf, size_t *rx_buf_len)
{
	struct tee_se_reader *r;
	TEE_Result ret;

	TEE_ASSERT(handle != NULL && handle->reader != NULL);
	ret = check_reader_state(handle);
	if (ret != TEE_SUCCESS)
		return ret;

	mutex_lock(&handle->mutex);
	r = handle->reader;

	TEE_ASSERT(r->ops->transmit);
	ret = r->ops->transmit(r, tx_buf, tx_buf_len, rx_buf, rx_buf_len);

	mutex_unlock(&handle->mutex);

	return ret;
}

void tee_se_reader_lock_basic_channel(struct tee_se_reader_handle *handle)
{
	TEE_ASSERT(handle != NULL);
	mutex_lock(&handle->mutex);
	handle->basic_channel_locked = true;
	mutex_unlock(&handle->mutex);
}

void tee_se_reader_unlock_basic_channel(struct tee_se_reader_handle *handle)
{
	TEE_ASSERT(handle != NULL);
	mutex_lock(&handle->mutex);
	handle->basic_channel_locked = false;
	mutex_unlock(&handle->mutex);
}

bool tee_se_reader_is_basic_channel_locked(struct tee_se_reader_handle *handle)
{
	TEE_ASSERT(handle != NULL);
	return handle->basic_channel_locked;
}

TEE_Result tee_se_reader_open_session(struct tee_ta_ctx *ctx,
		struct tee_se_reader_handle *handle,
		struct tee_se_session **session)
{
	TEE_Result ret;
	struct tee_se_session *s;

	TEE_ASSERT(session != NULL && *session == NULL);
	TEE_ASSERT(handle != NULL && handle->reader != NULL);

	s = alloc_tee_se_session(handle);
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = tee_se_reader_attach(handle);
	if (ret != TEE_SUCCESS)
		goto err_free_session;

	*session = s;

	if (ctx)
		add_tee_se_session(ctx, s);

	return TEE_SUCCESS;
err_free_session:
	free_tee_se_session(s);
	return ret;
}

void tee_se_reader_close_session(struct tee_ta_ctx *ctx,
		struct tee_se_session *session)
{
	struct tee_se_reader_handle *handle;

	TEE_ASSERT(session != NULL);

	handle = tee_se_session_get_reader_handle(session);
	TEE_ASSERT(handle->refcnt > 0);

	tee_se_reader_detach(handle);

	if (ctx)
		remove_tee_se_session(ctx, session);
	free_tee_se_session(session);
}

static void context_init(struct tee_se_manager_ctx *ctx)
{
	TAILQ_INIT(&ctx->reader_handles);
	mutex_init(&ctx->mutex);
}

static TEE_Result tee_se_manager_init(void)
{
	struct tee_se_manager_ctx *ctx = &se_manager_ctx;

	context_init(ctx);

	return TEE_SUCCESS;
}

service_init(tee_se_manager_init);
