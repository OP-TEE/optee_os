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

#include <kernel/tee_common.h>

#include "tee_api_types.h"
#include "tee_api_types.h"
#include "tee_ta.h"
#include <kernel/kta_types.h>
#include "tee_ta_manager_unpg.h"

/*-----------------------------------------------------------------------------
 * Initializes virtual memory management by reserving virtual memory for
 * memory areas not available TA virtual memroy allocation.
 *
 * Spare physical pages are passed in the memory range between ta_start and
 * ta_spare_end.  Spare physical pages are supposed to be mapped with "no
 * access" attribute.
 *
 * All addresses will be rounded up the the next page.
 *
 * Parameters:
 * ro_start - start of read only section for paging,
 * ro_end   - end of read only section for paging,
 * ta_start - start of section used for TA virtual memory
 * ta_spare_end - end of spare pages used for paging
 *
 * Returns:
 *        void
 *---------------------------------------------------------------------------*/
void tee_ta_vmem_init(tee_vaddr_t ro_start, tee_vaddr_t ro_end,
		      tee_vaddr_t ta_start, tee_vaddr_t ta_spare_end);

TEE_Result tee_ta_open_session(TEE_ErrorOrigin *err,
			       struct tee_ta_session **sess,
			       struct tee_ta_session_head *open_sessions,
			       const TEE_UUID *uuid,
			       const TEE_Identity *clnt_id,
			       uint32_t cancel_req_to,
			       struct tee_ta_param *param);

TEE_Result tee_ta_invoke_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess,
				 uint32_t cancel_req_to, uint32_t cmd,
				 struct tee_ta_param *param);

TEE_Result tee_ta_cancel_command(TEE_ErrorOrigin *err,
				 struct tee_ta_session *sess);

/*-----------------------------------------------------------------------------
 * Function called to close a TA.
 * Parameters:
 * id   - The session id (in)
 * Returns:
 *        TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_close_session(uint32_t id,
				struct tee_ta_session_head *open_sessions);

TEE_Result tee_ta_get_current_session(struct tee_ta_session **sess);

void tee_ta_set_current_session(struct tee_ta_session *sess);

TEE_Result tee_ta_get_client_id(TEE_Identity *id);

/*
 * Get pointer of executable part of the TA located in virtual kernel memory
 */
uintptr_t tee_ta_get_exec(const struct tee_ta_ctx *const ctx);

/* Returns OK is sess is a valid session pointer or static TA */
TEE_Result tee_ta_verify_session_pointer(struct tee_ta_session *sess,
					 struct tee_ta_session_head
					 *open_sessions);

int tee_ta_set_trace_level(int level);

#endif
