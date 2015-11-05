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

TEE_Result syscall_se_service_open(uint32_t *service_handle);

TEE_Result syscall_se_service_close(unsigned long service_handle);

TEE_Result syscall_se_service_get_readers(unsigned long service_handle,
			uint32_t *reader_handles, uint64_t *len);

TEE_Result syscall_se_reader_get_prop(unsigned long reader_handle, uint32_t *p);

TEE_Result syscall_se_reader_get_name(unsigned long reader_handle,
			char *name, uint64_t *name_len);

TEE_Result syscall_se_reader_open_session(unsigned long reader_handle,
			uint32_t *session_handle);

TEE_Result syscall_se_reader_close_sessions(unsigned long reader_handle);

TEE_Result syscall_se_session_is_closed(unsigned long session_handle);

TEE_Result syscall_se_session_get_atr(unsigned long session_handle,
			void *atr, uint64_t *atr_len);

TEE_Result syscall_se_session_open_channel(unsigned long session_handle,
			unsigned long is_logical, const void *aid_buf,
			size_t aid_buf_len, uint32_t *channel_handle);

TEE_Result syscall_se_session_close(unsigned long session_handle);

TEE_Result syscall_se_channel_select_next(unsigned long channel_handle);

TEE_Result syscall_se_channel_get_select_resp(unsigned long channel_handle,
			void *resp, uint64_t *resp_len);

TEE_Result syscall_se_channel_transmit(unsigned long channel_handle,
			void *cmd, unsigned long cmd_len, void *resp,
			uint64_t *resp_len);

TEE_Result syscall_se_channel_close(unsigned long channel_handle);

#else

#define  syscall_se_service_open		syscall_not_supported
#define  syscall_se_service_close		syscall_not_supported
#define  syscall_se_service_get_readers		syscall_not_supported
#define  syscall_se_reader_get_prop		syscall_not_supported
#define  syscall_se_reader_get_name		syscall_not_supported
#define  syscall_se_reader_open_session		syscall_not_supported
#define  syscall_se_reader_close_sessions	syscall_not_supported
#define  syscall_se_session_is_closed		syscall_not_supported
#define  syscall_se_session_get_atr		syscall_not_supported
#define  syscall_se_session_open_channel	syscall_not_supported
#define  syscall_se_session_close		syscall_not_supported
#define  syscall_se_channel_select_next		syscall_not_supported
#define  syscall_se_channel_get_select_resp	syscall_not_supported
#define  syscall_se_channel_transmit		syscall_not_supported
#define  syscall_se_channel_close		syscall_not_supported

#endif /* if defined(CFG_SE_API) */

#endif
