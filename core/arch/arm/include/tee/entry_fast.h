/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

/*
 * Fast call entry, __weak, overridable. If overridden should call
 * __tee_entry_fast() at the end in order to handle the standard functions.
 */
void tee_entry_fast(struct thread_smc_args *args);
void __tee_entry_fast(struct thread_smc_args *args);

#endif /* TEE_ENTRY_FAST_H */
