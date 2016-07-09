/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#ifndef TEE_COMMON_H
#define TEE_COMMON_H

#include <stdlib.h>

#ifdef MEASURE_TIME
/*
 * Initializes mesaure time. Initializes RTT0 to highest possible
 * resolution.
 */
void tee_mtime_init(void);

/*
 * Adds a time stamp together the description. Note that only the pointer
 * is copied, not the contents to minimize impact.
 */
void tee_mtime_stamp(const char *descr);

/*
 * Prints a report of measured times and reinitializes clears the table of
 * saved time stamps.
 */
void tee_mtime_report(void);

void tee_mtime_perftest(void);
#else
/* Empty macros to not have any impact on code when not meassuring time */
#define tee_mtime_init() do { } while (0)
#define tee_mtime_stamp(descr) do { } while (0)
#define tee_mtime_report() do { } while (0)
#define tee_mtime_perftest()  do { } while (0)
#endif

#endif /* TEE_COMMON_H */
