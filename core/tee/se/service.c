// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <assert.h>
#include <tee_api_types.h>
#include <trace.h>

#include <kernel/tee_ta_manager.h>
#include <kernel/user_ta.h>
#include <tee/se/service.h>
#include <tee/se/session.h>
#include <tee/se/reader.h>

#include "service_priv.h"
#include "reader_priv.h"
#include "session_priv.h"

TEE_Result tee_se_service_open(
		struct tee_se_service **service)
{
	TEE_Result ret;
	struct tee_se_service *h;
	struct tee_ta_session *sess;
	struct user_ta_ctx *utc;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;
	utc = to_user_ta_ctx(sess->ctx);

	assert(service);
	if (utc->se_service != NULL)
		return TEE_ERROR_ACCESS_CONFLICT;

	h = malloc(sizeof(struct tee_se_service));
	if (!h)
		return TEE_ERROR_OUT_OF_MEMORY;

	TAILQ_INIT(&h->opened_sessions);
	TAILQ_INIT(&h->closed_sessions);
	mutex_init(&h->mutex);
	*service = h;

	utc->se_service = h;

	return TEE_SUCCESS;
}

TEE_Result tee_se_service_add_session(
		struct tee_se_service *service,
		struct tee_se_session *session)
{
	assert(service && session);

	mutex_lock(&service->mutex);
	TAILQ_INSERT_TAIL(&service->opened_sessions, session, link);
	mutex_unlock(&service->mutex);

	return TEE_SUCCESS;
}

TEE_Result tee_se_service_is_session_closed(
		struct tee_se_service *service,
		struct tee_se_session *session)
{
	struct tee_se_session *s;

	TAILQ_FOREACH(s, &service->closed_sessions, link) {
		if (s == session)
			return TEE_SUCCESS;
	}

	return tee_se_reader_check_state(session->reader_proxy);
}

void tee_se_service_close_session(
		struct tee_se_service *service,
		struct tee_se_session *session)
{
	assert(service && session);

	tee_se_session_close(session);

	mutex_lock(&service->mutex);

	TAILQ_REMOVE(&service->opened_sessions,
			session, link);
	TAILQ_INSERT_TAIL(&service->closed_sessions,
			session, link);

	mutex_unlock(&service->mutex);
}

void tee_se_service_close_sessions_by_reader(
		struct tee_se_service *service,
		struct tee_se_reader_proxy *proxy)
{
	struct tee_se_session *s;

	assert(service && proxy);

	TAILQ_FOREACH(s, &service->opened_sessions, link) {
		if (s->reader_proxy == proxy)
			tee_se_service_close_session(service, s);
	}
}

TEE_Result tee_se_service_close(
		struct tee_se_service *service __unused)
{
	TEE_Result ret;
	struct tee_se_service *h;
	struct tee_se_session *s;
	struct tee_ta_session *sess;
	struct user_ta_ctx *utc;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return ret;

	utc = to_user_ta_ctx(sess->ctx);
	assert(utc->se_service);
	h = utc->se_service;

	/* clean up all sessions */
	mutex_lock(&h->mutex);
	TAILQ_FOREACH(s, &h->opened_sessions, link) {
		TAILQ_REMOVE(&h->opened_sessions, s, link);
		tee_se_session_close(s);
	}

	TAILQ_FOREACH(s, &h->closed_sessions, link)
		TAILQ_REMOVE(&h->closed_sessions, s, link);

	mutex_unlock(&h->mutex);

	free(h);

	return TEE_SUCCESS;
}

bool tee_se_service_is_valid(struct tee_se_service *service)
{
	TEE_Result ret;
	struct tee_ta_session *sess;

	ret = tee_ta_get_current_session(&sess);
	if (ret != TEE_SUCCESS)
		return false;

	if (to_user_ta_ctx(sess->ctx)->se_service == service)
		return true;
	else
		return false;
}

bool tee_se_service_is_session_valid(
		struct tee_se_service *service,
		struct tee_se_session *session_service)
{
	struct tee_se_session *sh;

	TAILQ_FOREACH(sh, &service->opened_sessions, link) {
		if (sh == session_service)
			return true;
	}
	TAILQ_FOREACH(sh, &service->closed_sessions, link) {
		if (sh == session_service)
			return true;
	}
	return false;
}

bool tee_se_service_is_channel_valid(struct tee_se_service *service,
		struct tee_se_channel *channel)
{
	struct tee_se_session *s;

	TAILQ_FOREACH(s, &service->opened_sessions, link) {
		if (tee_se_session_is_channel_exist(s, channel))
			return true;
	}

	return false;
}
