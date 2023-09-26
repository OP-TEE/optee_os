/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 */

#ifndef TEEABI_H
#define TEEABI_H

#include <compiler.h>

/*
 * Implement based on the transport method used to communicate between
 * untrusted domain and trusted domain. It could be an SBI/ECALL-based to
 * a security monitor running in M-Mode and panic or messaging-based across
 * domains where we return to a messaging callback which parses and handles
 * messages.
 */
void __weak teeabi_return_to_ree(unsigned long arg0 __maybe_unused,
				 unsigned long arg1 __maybe_unused,
				 unsigned long arg2 __maybe_unused,
				 unsigned long arg3 __maybe_unused,
				 unsigned long arg4 __maybe_unused,
				 unsigned long arg5 __maybe_unused);

#endif /*TEEABI_H*/
