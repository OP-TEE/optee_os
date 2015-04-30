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
#ifndef TEE_DISPATCH_H
#define TEE_DISPATCH_H

#include <stdarg.h>
#include <kernel/tee_common_unpg.h>
#include <tee_api_types.h>

#include <trace.h>

/*
 * output argument data structure is always TEE service specific but always
 * starts with the generic output data structure tee_dispatch_out.
 */
struct tee_dispatch_out {
	uint32_t duration;
	TEE_Result res;
	TEE_ErrorOrigin err;
};

/* Input arg structure specific to TEE service 'open session'. */
struct tee_dispatch_open_session_in {
	TEE_UUID uuid;
	uint32_t param_types;
	TEE_Param params[4];
	TEE_Identity clnt_id;
	uint32_t param_attr[4];
};

/* Output arg structure specific to TEE service 'open session'. */
struct tee_dispatch_open_session_out {
	struct tee_dispatch_out msg;
	TEE_Session *sess;
	TEE_Param params[4];
};

/* Input arg structure specific to TEE service 'invoke command'. */
struct tee_dispatch_invoke_command_in {
	TEE_Session *sess;
	uint32_t cmd;
	uint32_t param_types;
	TEE_Param params[4];
	uint32_t param_attr[4];
};

/* Output arg structure specific to TEE service 'invoke command'. */
struct tee_dispatch_invoke_command_out {
	struct tee_dispatch_out msg;
	TEE_Param params[4];
};

/* Input arg structure specific to TEE service 'cancel command'. */
struct tee_dispatch_cancel_command_in {
	TEE_Session *sess;
};

/* Output arg structure specific to TEE service 'cancel command'. */
struct tee_dispatch_cancel_command_out {
	struct tee_dispatch_out msg;
};

/* Input arg structure specific to TEE service 'close session'. */
struct tee_close_session_in {
	TEE_Session *sess;
};

/* Input arg structure specific to TEE service 'register shared memory'. */
struct tee_dispatch_memory_in {
	void *buffer;
	uint32_t size;
};

TEE_Result tee_dispatch_open_session(struct tee_dispatch_open_session_in *in,
				     struct tee_dispatch_open_session_out *out);
TEE_Result tee_dispatch_close_session(struct tee_close_session_in *in);
TEE_Result tee_dispatch_invoke_command(struct tee_dispatch_invoke_command_in
				       *in,
				       struct tee_dispatch_invoke_command_out
				       *out);
TEE_Result tee_dispatch_cancel_command(struct tee_dispatch_cancel_command_in
				       *in,
				       struct tee_dispatch_cancel_command_out
				       *out);

#endif /* TEE_DISPATCH_H */
