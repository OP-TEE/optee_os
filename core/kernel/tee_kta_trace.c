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

#include <stdarg.h>

#include <kernel/tee_ta_manager.h>
#include <kernel/tee_kta_trace.h>

/*****************************************************************************/

/* Default trace level */
int _ta_trace_level = CFG_TEE_TA_LOG_LEVEL;

/*****************************************************************************/

void ta_trace_test(void)
{
	TAINMSG("level: [%d]", _ta_trace_level);
	ITAMSG("current trace level = %d", _ta_trace_level);
	ITAMSG("Without args");
	ATAMSG("[%d] and [%s]", TRACE_ALWAYS, "TRACE_ALWAYS");
	ETAMSG("[%d] and [%s]", TRACE_ERROR, "TRACE_ERROR");
	ITAMSG("[%d] and [%s]", TRACE_INFO, "TRACE_INFO");
	DTAMSG("[%d] and [%s]", TRACE_DEBUG, "TRACE_DEBUG");
	FTAMSG("[%d] and [%s]", TRACE_FLOW, "TRACE_FLOW");
	ATAMSG_RAW("raw trace in KERNEL-TA with level [%s]", "TRACE_ALWAYS");
	ATAMSG_RAW(" __ end of raw trace\n");
	DTAMSG_RAW("raw trace in KERNEL-TA with level [%s]", "TRACE_DEBUG");
	DTAMSG_RAW(" __ end of raw trace\n");
	TAOUTMSG("");
}

/*****************************************************************************/

void set_ta_trace_level(int level)
{
	if ((level <= CFG_TEE_TA_LOG_LEVEL) &&
	    (level >= TRACE_MIN) &&
	    (level <= TRACE_MAX))
		_ta_trace_level = level;
	else {
		ATAMSG("Can't set level [%d]", level);
		return;
	}

	/* parse all loaded TAs to set TA trace level */
	(void)tee_ta_set_trace_level(level);

	ta_trace_test();
	ATAMSG_RAW("\nLevel set to [%d]\n", _ta_trace_level);
}

int get_ta_trace_level(void)
{
	return _ta_trace_level;
}

#if (CFG_TEE_CORE_LOG_LEVEL == 0)
/* no log, sorry! implement a dummy _dprintf */
int _dprintf(const char *function, int line, int level, const char *prefix,
	     const char *fmt, ...)
{
	return 0;
}
#endif
/*****************************************************************************/
