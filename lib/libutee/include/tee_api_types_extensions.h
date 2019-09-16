/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TEE_API_TYPES_EXTENSIONS_H__
#define __TEE_API_TYPES_EXTENSIONS_H__

/*
 * The type of opaque handles on TA Session. These handles are returned by
 * the function TEE_OpenREESession.
 */
typedef struct __ree_session_handle *ree_session_handle;

#endif
