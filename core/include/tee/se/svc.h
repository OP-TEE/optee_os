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

#ifndef TEE_SVC_SE_H
#define TEE_SVC_SE_H

#include <tee_api_types.h>

#include <tee/se/service.h>
#include <tee/se/manager.h>
#include <tee/se/reader.h>
#include <tee/se/session.h>
#include <tee/se/channel.h>
#include <tee/se/aid.h>
#include <tee/se/apdu.h>
#include <tee/se/util.h>

#if defined(CFG_SE_API)

TEE_Result tee_svc_se_service_open(uint32_t *service_handle);

TEE_Result tee_svc_se_service_close(uint32_t service_handle);

TEE_Result tee_svc_se_service_get_readers(uint32_t service_handle,
		uint32_t *reader_handles, size_t *len);

TEE_Result tee_svc_se_reader_get_prop(uint32_t reader_handle,
		TEE_SEReaderProperties *p);

TEE_Result tee_svc_se_reader_get_name(uint32_t reader_handle,
		char *name, size_t *name_len);

TEE_Result tee_svc_se_reader_open_session(uint32_t reader_handle,
		uint32_t *session_handle);

TEE_Result tee_svc_se_reader_close_sessions(uint32_t reader_handle);

TEE_Result tee_svc_se_session_is_closed(uint32_t session_handle);

TEE_Result tee_svc_se_session_get_atr(uint32_t session_handle,
		void *atr, size_t *atr_len);

TEE_Result tee_svc_se_session_open_channel(
		uint32_t session_handle, bool is_logical,
		TEE_SEAID *aid, uint32_t *channel_handle);

TEE_Result tee_svc_se_session_close(uint32_t session_handle);

TEE_Result tee_svc_se_channel_select_next(uint32_t channel_handle);

TEE_Result tee_svc_se_channel_get_select_resp(uint32_t channel_handle,
	void *resp, size_t *resp_len);

TEE_Result tee_svc_se_channel_transmit(uint32_t channel_handle,
	void *cmd, size_t cmd_len, void *resp, size_t *resp_len);

TEE_Result tee_svc_se_channel_close(uint32_t channel_handle);

#else

#define  tee_svc_se_service_open		tee_svc_not_supported
#define  tee_svc_se_service_close		tee_svc_not_supported
#define  tee_svc_se_service_get_readers		tee_svc_not_supported
#define  tee_svc_se_reader_get_prop		tee_svc_not_supported
#define  tee_svc_se_reader_get_name		tee_svc_not_supported
#define  tee_svc_se_reader_open_session		tee_svc_not_supported
#define  tee_svc_se_reader_close_sessions	tee_svc_not_supported
#define  tee_svc_se_session_is_closed		tee_svc_not_supported
#define  tee_svc_se_session_get_atr		tee_svc_not_supported
#define  tee_svc_se_session_open_channel	tee_svc_not_supported
#define  tee_svc_se_session_close		tee_svc_not_supported
#define  tee_svc_se_channel_select_next		tee_svc_not_supported
#define  tee_svc_se_channel_get_select_resp	tee_svc_not_supported
#define  tee_svc_se_channel_transmit		tee_svc_not_supported
#define  tee_svc_se_channel_close		tee_svc_not_supported

#endif /* if defined(CFG_SE_API) */

#endif
