/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef TRACE_TA_H
#define TRACE_TA_H

#include <trace.h>

/* Macros to trace TA related events, logs, TA crash info etc */
#ifdef CFG_TEE_CORE_TA_TRACE
#define TAMSG(...)	EMSG(__VA_ARGS__)
#define TAMSG_RAW(...)	EMSG_RAW(__VA_ARGS__)
#else
#define TAMSG(...)
#define TAMSG_RAW(...)
#endif

#endif /*TRACE_TA_H*/

