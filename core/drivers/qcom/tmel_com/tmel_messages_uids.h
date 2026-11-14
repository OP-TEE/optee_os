/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_MESSAGES_UIDS_H
#define __TMEL_MESSAGES_UIDS_H

#include <util.h>

/*
 * TME_MSG_UID bit layout:
 *   [31:16] reserved
 *   [15:8]  msg_type
 *   [7:0]   action_id
 */

#define TME_MSG_UID_CREATE(m, a) \
	((uint32_t)((((uint32_t)m) & 0xff) << 8) | (((uint32_t)a) & 0xff))

#define TME_MSG_UID_MSG_TYPE(v)      ((((uint32_t)v) & \
				      GENMASK_32(15, 8)) >> 8)

#define TME_MSG_UID_ACTION_ID(v) \
	(((uint32_t)v) & GENMASK_32(7, 0))

#define TME_MSG_KM			0x07 /* Key management services */
#define TME_MSG_HCS			0x0B /* Host crypto services */

#define TME_ACTION_KM_CLEAR				0x01
#define TME_ACTION_KM_DERIVE				0x04
#define TME_ACTION_KM_DISTRIBUTE			0x07

#define TME_ACTION_HCS_RNG_GET				0x0C

/* Message: struct tmel_rng_get_msg */
#define TME_MSG_UID_HCS_RNG_GET \
		TME_MSG_UID_CREATE(TME_MSG_HCS, \
		TME_ACTION_HCS_RNG_GET)

/* Message: struct tmel_km_clear_key_msg */
#define TME_MSG_UID_KM_CLEAR \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_CLEAR)

/* Message: struct tmel_km_derive_key_msg */
#define TME_MSG_UID_KM_DERIVE \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_DERIVE)

/* Message: struct tmel_km_distribute_key_msg */
#define TME_MSG_UID_KM_DISTRIBUTE \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_DISTRIBUTE)

#endif /* __TMEL_MESSAGES_UIDS_H */
