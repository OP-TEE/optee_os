/*
 * Copyright 2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
*
* @par Description
* This file implements implements platform independent sleep functionality
* @par History
*
*****************************************************************************/

#include <stdint.h>
#if defined(__gnu_linux__) || defined(__clang__)
#include <unistd.h>
#endif
#include <time.h>
#include "sm_timer.h"

/* initializes the system tick counter
 * return 0 on succes, 1 on failure */
uint32_t sm_initSleep()
{
    return 0;
}

/**
 * Implement a blocking (for the calling thread) wait for a number of milliseconds.
 */
void sm_sleep(uint32_t msec)
{
#if defined(__gnu_linux__) || defined __clang__
    useconds_t microsec = msec*1000;
    usleep(microsec);
#else
    clock_t goal = msec + clock();
    while (goal > clock());
#endif
}

/**
 * Implement a blocking (for the calling thread) wait for a number of microseconds
 */
void sm_usleep(uint32_t microsec)
{
#if defined(__gnu_linux__) || defined __clang__
    usleep(microsec);
#elif defined(_WIN32)
	#pragma message ( "No sm_usleep implemented" )
#elif defined(__OpenBSD__)
	#warning "No sm_usleep implemented"
#else
	//#warning "No sm_usleep implemented"
#endif
}
