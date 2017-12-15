/* SPDX-License-Identifier: BSD-2-Clause */
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
