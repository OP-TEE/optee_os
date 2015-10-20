/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef TEE_TA_MANAGER_H
#define TEE_TA_MANAGER_H

#include <tee_api_types.h>
#include <utee_types.h>
#include <kernel/tee_common.h>
#include <kernel/tee_ta_manager_unpg.h>

/* Magic TEE identity pointer: set when teecore requests a TA close */
#define KERN_IDENTITY	((TEE_Identity *)-1)
/* Operation is initiated by a client (non-secure) app */
#define NSAPP_IDENTITY	(NULL)

TEE_Result tee_ta_open_session(TEE_ErrorOrigin *err,
			       struct tee_ta_session **sess,
			       struct tee_ta_session_head *open_sessions,
			       const TEE_UUID *uuid,
			       const TEE_Identity *clnt_id,
			       uint32_t cancel_req_to,
			       struct tee_ta_param *param);

TEE_Result tee_ta_invoke_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id,
				 uint32_t cancel_req_to, uint32_t cmd,
				 struct tee_ta_param *param);

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 const TEE_Identity *clnt_id);

/*-----------------------------------------------------------------------------
 * Function called to close a TA.
 * Parameters:
 * id   - The session id (in)
 * Returns:
 *        TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_close_session(struct tee_ta_session *sess,
				struct tee_ta_session_head *open_sessions,
				const TEE_Identity *clnt_id);

TEE_Result tee_ta_get_current_session(struct tee_ta_session **sess);

void tee_ta_set_current_session(struct tee_ta_session *sess);

TEE_Result tee_ta_get_client_id(TEE_Identity *id);

/* Returns OK is sess is a valid session pointer or static TA */
TEE_Result tee_ta_verify_session_pointer(struct tee_ta_session *sess,
					 struct tee_ta_session_head
					 *open_sessions);

int tee_ta_set_trace_level(int level);
void tee_ta_dump_current(void);
void tee_ta_dump_all(void);

#ifdef CFG_CACHE_API
TEE_Result tee_uta_cache_operation(struct tee_ta_session *s,
				   enum utee_cache_operation op,
				   void *va, size_t len);
#endif

#endif
