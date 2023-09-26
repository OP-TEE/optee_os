// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 */

#include <tee/teeabi.h>

void __weak teeabi_return_to_ree(unsigned long arg0 __maybe_unused,
				 unsigned long arg1 __maybe_unused,
				 unsigned long arg2 __maybe_unused,
				 unsigned long arg3 __maybe_unused,
				 unsigned long arg4 __maybe_unused,
				 unsigned long arg5 __maybe_unused)
{
}
