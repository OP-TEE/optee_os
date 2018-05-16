/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_ENTRY_STD_H
#define TEE_ENTRY_STD_H

#include <kernel/thread.h>

/* Standard call entry */
void tee_entry_std(struct thread_smc_args *args);

#endif /* TEE_ENTRY_STD_H */
