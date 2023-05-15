/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef FTRACE_H
#define FTRACE_H

void ftrace_enter(unsigned long pc, unsigned long *lr);

#endif /* FTRACE_H */
