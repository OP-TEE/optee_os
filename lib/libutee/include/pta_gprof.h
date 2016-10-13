/*
 * Copyright (c) 2016, Linaro Limited
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
