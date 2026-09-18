/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * TME message unique identifiers and their parameter descriptors.
 */

#ifndef TMEMESSAGESUIDS_H
#define TMEMESSAGESUIDS_H

#include <util.h>

/*
 * TME Messages Unique Identifiers bit layout
 *  _____________________________________
 * |___________|____________|___________|
 * | 31------16| 15-------8 | 7-------0 |
 * | Reserved  |messageType | actionID  |
 * |___________|____________|___________|
 *	       \___________  ___________/
 *			   \/
 *		      TME_MSG_UID
 */

/*
 * TME Messages Unique Identifiers Parameter ID bit layout
 * __________________________________________________________________________
 * |     |     |     |     |     |     |     |     |     |     |     |    |
 * |31-30|29-28|27-26|25-24|23-22|21-20|19-18|17-16|15-14|13-12|11-10|9--8|
 * | p14 | p13 | p12 | p11 | p10 | p9  | p8  | p7  | p6  | p5  | p4  | p3 |
 * |type |type |type |type |type |type |type |type |type |type |type |type|
 * |_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|_____|____|
 *  ____________
 * |    |       |
 * |7--6|3-----0|
 * | p2 | nargs |
 * |type|       |
 * |____|_______|
 */

/*
 * Macro used to define unique TME Message Identifier based on
 * message type and action identifier.
 */
#define TME_MSG_UID_CREATE(m, a) \
	((uint32_t)((((uint32_t)m) & 0xff) << 8) | (((uint32_t)a) & 0xff))

/* Helper macro to extract the messageType from TME_MSG_UID. */
#define TME_MSG_UID_MSG_TYPE(v)      ((((uint32_t)v) & \
				      GENMASK_32(15, 8)) >> 8)

/* Helper macro to extract the actionID from TME_MSG_UID. */
#define TME_MSG_UID_ACTION_ID(v) \
	(((uint32_t)v) & GENMASK_32(7, 0))

/*
 * Helper Macros to create paramID for every unique TME Message Identifier.
 */
/*
 * A parameter of type value. TME receive data as part of request,
 * can also use to send response.
 */
#define TME_MSG_PARAM_TYPE_VAL                0x0
/*
 * A parameter of type input only. TME receive data through buffer as part
 * of request, doesn't send response through it. It consist of 2 actual
 * uint32_t param (ipBufAddr & ipBufLen)
 * ipBufAddr  - Address of the buffer. TME shouldn't change it.
 * ipBufLen   - Byte length of input data to be consumed by TME.
 *		TME shouldn't change it.
 */
#define TME_MSG_PARAM_TYPE_BUF_IN             0x1
/*
 * A parameter of type output only. TME doesn't receive data through buffer
 * as part of request, instead use this buffer to send response.
 * It consist of 3 actual uint32_t param (outBufAddr, outBufLen &
 * outBufOutLen).
 * outBufAddr   - Address of the buffer. TME shouldn't change it.
 * outBufLen    - Indiactes actual/allocated size of the buffer,
 *		  TME shouldn't change it.
 * outBufOutLen - TME update to actual out data length in byte.
 */
#define TME_MSG_PARAM_TYPE_BUF_OUT            0x2
/*
 * A parameter of type both input & output. TME can receive data through
 * the buffer, as well can use this buffer to send response.
 * It consist of 3 actual uint32_t param (inOutBufAddr, inOutBufLen &
 * inOutBufInOutLen).
 * inOutBufAddr     - Address of the buffer. TME shouldn't change it.
 * inOutBufLen      - Indiactes actual/allocated size of the buffer,
 *		      TME shouldn't change it.
 * inOutBufInOutLen - can hold actual input data length during request
 *		      & TME update to actual out data length in byte for a
 *		      response.
 */
#define TME_MSG_PARAM_TYPE_BUF_IN_OUT         0x3

/* Parameter ID nargs bitmask. */
#define TME_MSG_PARAM_ID_NARGS_MASK        GENMASK_32(3, 0)
/* Parameter ID parameter type bitmask. */
#define TME_MSG_PARAM_ID_PARAM_TYPE_MASK   GENMASK_32(1, 0)

/* Internal helper macro for __TME_MSG_CREATE_PARAM_ID. */
#define _TME_MSG_CREATE_PARAM_ID(nargs, p1, p2, p3, p4, p5, p6, p7, \
				 p8, p9, p10, p11, p12, p13, p14, ...) \
	(((nargs) & TME_MSG_PARAM_ID_NARGS_MASK) + \
	(((p1) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 4) +  \
	(((p2) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 6) +  \
	(((p3) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 8) +  \
	(((p4) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 10) + \
	(((p5) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 12) + \
	(((p6) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 14) + \
	(((p7) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 16) + \
	(((p8) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 18) + \
	(((p9) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 20) + \
	(((p10) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 22) + \
	(((p11) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 24) + \
	(((p12) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 26) + \
	(((p13) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 28) + \
	(((p14) & TME_MSG_PARAM_ID_PARAM_TYPE_MASK) << 30))

/* Internal helper macro to get nargs from paramID */
#define TME_MSG_PARAM_ID_GET_NARGS(v) \
		(((uint32_t)v) & TME_MSG_PARAM_ID_NARGS_MASK)

/* Internal helper macro to get ith parameter from paramID */
#define TME_MSG_PARAM_ID_GET_PARAM_TYPEI(v, i) \
		((((uint32_t)v) >> ((2 * (i)) + 4)) & \
		 TME_MSG_PARAM_ID_PARAM_TYPE_MASK)

/* Internal helper macro for TME_MSG_CREATE_PARAM_ID_X */
#define __TME_MSG_CREATE_PARAM_ID(...) \
	_TME_MSG_CREATE_PARAM_ID(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
				 0, 0, 0, 0)

/* Build a paramID from the argument count and per-parameter types */
#define TME_MSG_CREATE_PARAM_ID_0 \
	__TME_MSG_CREATE_PARAM_ID(0)
#define TME_MSG_CREATE_PARAM_ID_1(p1) \
	__TME_MSG_CREATE_PARAM_ID(1, p1)
#define TME_MSG_CREATE_PARAM_ID_2(p1, p2) \
	__TME_MSG_CREATE_PARAM_ID(2, p1, p2)
#define TME_MSG_CREATE_PARAM_ID_3(p1, p2, p3) \
	__TME_MSG_CREATE_PARAM_ID(3, p1, p2, p3)
#define TME_MSG_CREATE_PARAM_ID_4(p1, p2, p3, p4) \
	__TME_MSG_CREATE_PARAM_ID(4, p1, p2, p3, p4)
#define TME_MSG_CREATE_PARAM_ID_5(p1, p2, p3, p4, p5) \
	__TME_MSG_CREATE_PARAM_ID(5, p1, p2, p3, p4, p5)
#define TME_MSG_CREATE_PARAM_ID_6(p1, p2, p3, p4, p5, p6) \
	__TME_MSG_CREATE_PARAM_ID(6, p1, p2, p3, p4, p5, p6)
#define TME_MSG_CREATE_PARAM_ID_7(p1, p2, p3, p4, p5, p6, p7) \
	__TME_MSG_CREATE_PARAM_ID(7, p1, p2, p3, p4, p5, p6, p7)
#define TME_MSG_CREATE_PARAM_ID_8(p1, p2, p3, p4, p5, p6, p7, p8) \
	__TME_MSG_CREATE_PARAM_ID(8, p1, p2, p3, p4, p5, p6, p7, p8)
#define TME_MSG_CREATE_PARAM_ID_9(p1, p2, p3, p4, p5, p6, p7, p8, p9) \
	__TME_MSG_CREATE_PARAM_ID(9, p1, p2, p3, p4, p5, p6, p7, p8, p9)
#define TME_MSG_CREATE_PARAM_ID_10(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10) \
	__TME_MSG_CREATE_PARAM_ID(10, p1, p2, p3, p4, p5, p6, p7, \
				  p8, p9, p10)
#define TME_MSG_CREATE_PARAM_ID_11(p1, p2, p3, p4, p5, p6, p7, p8, p9, \
				   p10, p11) \
	__TME_MSG_CREATE_PARAM_ID(11, p1, p2, p3, p4, p5, p6, p7, \
				  p8, p9, p10, p11)
#define TME_MSG_CREATE_PARAM_ID_12(p1, p2, p3, p4, p5, p6, p7, p8, p9, \
				   p10, p11, p12) \
	__TME_MSG_CREATE_PARAM_ID(12, p1, p2, p3, p4, p5, p6, p7, \
				  p8, p9, p10, p11, p12)
#define TME_MSG_CREATE_PARAM_ID_13(p1, p2, p3, p4, p5, p6, p7, p8, p9, \
				   p10, p11, p12, p13) \
	__TME_MSG_CREATE_PARAM_ID(13, p1, p2, p3, p4, p5, p6, p7, \
				  p8, p9, p10, p11, p12, p13)
#define TME_MSG_CREATE_PARAM_ID_14(p1, p2, p3, p4, p5, p6, p7, p8, p9, \
				   p10, p11, p12, p13, p14) \
	__TME_MSG_CREATE_PARAM_ID(14, p1, p2, p3, p4, p5, p6, p7, \
				  p8, p9, p10, p11, p12, p13, p14)

/*
 * Supported messageType's.
 *
 * <Template> : TME_MSG_<MSGTYPE_NAME>
 */
#define TME_MSG_KM			0x07 /* Key management services */
#define TME_MSG_HCS			0x0B /* Host crypto services */

/*
 * Action ID's per messageType.
 *
 * <Template> : TME_ACTION_<MSGTYPE_NAME>_<ACTIONID_NAME>
 */

/* Action ID's for TME_MSG_KM */
#define TME_ACTION_KM_CLEAR				0x01
#define TME_ACTION_KM_DERIVE				0x04
#define TME_ACTION_KM_DISTRIBUTE			0x07

/* Action ID's for TME_MSG_HCS */
#define TME_ACTION_HCS_RNG_GET				0x0C

/*
 * TME Message UID's (messageType | actionID) and their paramID's.
 *
 * <Template> : TME_MSG_UID_<MSGTYPE_NAME>_<ACTIONID_NAME>
 * <Template> : TME_MSG_UID_<MSGTYPE_NAME>_<ACTIONID_NAME>_PARAM_ID
 */

/*
 * Get RNG number
 * @param_id {length, outBuf, status,
 *	      {tmeErrorStatus, seqErrorStatus, seqKPErrorStatus0,
 *	      seqKPErrorStatus1, seqRspStatus}}
 * ref: TMERNGGetMessage_t
 */
#define TME_MSG_UID_HCS_RNG_GET \
		TME_MSG_UID_CREATE(TME_MSG_HCS, \
		TME_ACTION_HCS_RNG_GET)

#define TME_MSG_UID_HCS_RNG_GET_PARAM_ID \
		(TME_MSG_CREATE_PARAM_ID_8( \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_BUF_OUT, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL))

/*
 * Clear Key (TMEKMClearKeyMessage_t)
 * @param_id {keyId, status,
 *	      {tmeErrorStatus, seqErrorStatus, seqKPErrorStatus0,
 *	      seqKPErrorStatus1, seqRspStatus}}
 */
#define TME_MSG_UID_KM_CLEAR \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_CLEAR)
#define TME_MSG_UID_KM_CLEAR_PARAM_ID \
		TME_MSG_CREATE_PARAM_ID_7( \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL)

/*
 * Derive Key (TMEKMDeriveKeyMessage_t)
 * @param_id {keyID, kdfInfo, cred, keyID, status,
 *	      {tmeErrorStatus, seqErrorStatus, seqKPErrorStatus0,
 *	      seqKPErrorStatus1, seqRspStatus}}
 */
#define TME_MSG_UID_KM_DERIVE \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_DERIVE)
#define TME_MSG_UID_KM_DERIVE_PARAM_ID \
		TME_MSG_CREATE_PARAM_ID_10( \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_BUF_IN, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL)

/*
 * Distribute Key (TMEKMDistributeKeyMessage_t)
 * @param_id {keyID, dstID, index, status,
 *	      {tmeErrorStatus, seqErrorStatus, seqKPErrorStatus0,
 *	      seqKPErrorStatus1, seqRspStatus}}
 */
#define TME_MSG_UID_KM_DISTRIBUTE \
		TME_MSG_UID_CREATE(TME_MSG_KM, \
		TME_ACTION_KM_DISTRIBUTE)
#define TME_MSG_UID_KM_DISTRIBUTE_PARAM_ID \
		TME_MSG_CREATE_PARAM_ID_9( \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL, \
			TME_MSG_PARAM_TYPE_VAL)

#endif /* TMEMESSAGESUIDS_H */
