/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef SM_PRIVATE_H
#define SM_PRIVATE_H

/* Returns one of SM_EXIT_TO_* exit monitor in secure or non-secure world */
uint32_t sm_from_nsec(struct sm_ctx *ctx);
#endif /*SM_PRIVATE_H*/

