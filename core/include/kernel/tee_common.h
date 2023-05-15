/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
