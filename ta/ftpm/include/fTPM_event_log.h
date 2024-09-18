/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FTPM_EVENT_LOG_
#define _FTPM_EVENT_LOG_

bool process_eventlog(const unsigned char *const buf, const size_t log_size);
void dump_event_log(uint8_t *log_addr, size_t log_size);

#endif /* _FTPM_EVENT_LOG_*/
