/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_SE_SERVICE_H
#define TEE_SE_SERVICE_H

#include <tee_api_types.h>
#include <kernel/mutex.h>

struct tee_se_service;
struct tee_se_session;
struct tee_se_channel;
struct tee_se_reader_proxy;

TEE_Result tee_se_service_open(
		struct tee_se_service **service);

TEE_Result tee_se_service_add_session(
		struct tee_se_service *service,
		struct tee_se_session *session);

void tee_se_service_close_session(
		struct tee_se_service *service,
		struct tee_se_session *session);

void tee_se_service_close_sessions_by_reader(
		struct tee_se_service *service,
		struct tee_se_reader_proxy *proxy);

TEE_Result tee_se_service_is_session_closed(
		struct tee_se_service *service,
		struct tee_se_session *session_service);

TEE_Result tee_se_service_close(
		struct tee_se_service *service);

bool tee_se_service_is_valid(
		struct tee_se_service *service);

bool tee_se_service_is_session_valid(
		struct tee_se_service *service,
		struct tee_se_session *session_service);

bool tee_se_service_is_channel_valid(
		struct tee_se_service *service,
		struct tee_se_channel *channel);

#endif
