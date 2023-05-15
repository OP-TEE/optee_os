/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __PTA_GPROF_H
#define __PTA_GPROF_H

/*
 * Interface to the gprof pseudo-TA, which is used by libutee to control TA
 * profiling and forward data to tee-supplicant.
 */

#define PTA_GPROF_UUID { 0x2f6e0d48, 0xc574, 0x426d, { \
			 0x82, 0x4e, 0x40, 0x19, 0x8c, 0xde, 0x5c, 0xac } }

/*
 * Send TA profiling data (gmon.out format) to tee-supplicant
 * Data may be sent in several chunks: first set id to 0, then re-use the
 * allocated value in subsequent calls.
 *
 * [in/out] value[0].a: id
 * [in]     memref[1]: profiling data
 */
#define PTA_GPROF_SEND			0

/*
 * Start PC sampling of a user TA session
 *
 * [in/out] memref[0]: sampling buffer
 * [in]     value[1].a: offset: the lowest PC value in the TA
 * [in]     value[1].b: scale: histogram scaling factor
 */
#define PTA_GPROF_START_PC_SAMPLING	1

/*
 * Stop PC sampling of a user TA session and retrieve data
 *
 * [out] value[0].a: sampling frequency
 */
#define PTA_GPROF_STOP_PC_SAMPLING	2

#endif /* __PTA_GPROF_H */
