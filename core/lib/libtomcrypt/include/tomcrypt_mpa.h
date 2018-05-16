/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TOMCRYPT_MPA_H_
#define TOMCRYPT_MPA_H_

#include <mpalib.h>
#include "tomcrypt.h"

extern mpa_scratch_mem external_mem_pool;

void init_mpa_tomcrypt(mpa_scratch_mem pool);

#endif /* TOMCRYPT_MPA_H_ */
