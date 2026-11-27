/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_MESSAGES_UIDS_H
#define __TMEL_MESSAGES_UIDS_H

#include <util.h>

/*
 * TME_MSG_UID_*() - Build and split a message UID
 *
 * Layout:
 *   [31:16] reserved
 *   [15:8]  msg_type
 *   [7:0]   action_id
 */
#define TME_MSG_UID_CREATE(m, a) \
	((((m) & 0xffU) << 8) | ((a) & 0xffU))

#define TME_MSG_UID_MSG_TYPE(v)		(((v) & GENMASK_32(15, 8)) >> 8)

#define TME_MSG_UID_ACTION_ID(v)	((v) & GENMASK_32(7, 0))

#endif /* __TMEL_MESSAGES_UIDS_H */
