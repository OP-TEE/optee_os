/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
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

#ifndef TEE_ENTRY_FAST_H
#define TEE_ENTRY_FAST_H

#include <kernel/thread.h>

/* These functions are overridable by the specific target */
void tee_entry_get_api_call_count(struct thread_smc_args *args);
void tee_entry_get_api_uuid(struct thread_smc_args *args);
void tee_entry_get_api_revision(struct thread_smc_args *args);
void tee_entry_get_os_uuid(struct thread_smc_args *args);
void tee_entry_get_os_revision(struct thread_smc_args *args);

/*
 * Returns the number of calls recognized by tee_entry(). Used by the
 * specific target to calculate the total number of supported calls when
 * overriding tee_entry_get_api_call_count().
 */
size_t tee_entry_generic_get_api_call_count(void);

/* Fast call entry */
void tee_entry_fast(struct thread_smc_args *args);

#endif /* TEE_ENTRY_FAST_H */
