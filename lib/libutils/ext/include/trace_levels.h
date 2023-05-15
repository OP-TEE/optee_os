/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TRACE_LEVELS_H
#define TRACE_LEVELS_H

/*
 * Trace levels.
 *
 * ALWAYS is used when you always want a print to be seen, but it is not always
 * an error.
 *
 * ERROR is used when some kind of error has happened, this is most likely the
 * print you will use most of the time when you report some kind of error.
 *
 * INFO is used when you want to print some 'normal' text to the user.
 * This is the default level.
 *
 * DEBUG is used to print extra information to enter deeply in the module.
 *
 * FLOW is used to print the execution flox, typically the in/out of functions.
 *
 */

#define TRACE_MIN       0
#define TRACE_ERROR     1
#define TRACE_INFO      2
#define TRACE_DEBUG     3
#define TRACE_FLOW      4
#define TRACE_MAX       TRACE_FLOW

/* Trace level of the casual printf */
#define TRACE_PRINTF_LEVEL TRACE_ERROR

#endif /*TRACE_LEVELS_H*/
