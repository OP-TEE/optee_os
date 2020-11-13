/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Huawei Technologies Co. Ltd.
 */

#include <asm.S>

/*
 * long tlsdesc_resolve(struct tlsdesc *);
 *
 * Must preserve all registers except x0, x1 and the processor flags.
 * See https://www.fsfla.org/~lxoliva/writeups/TLS/RFC-TLSDESC-ARM.txt section
 * "Resolvers' Calling Convention". The document applies to 32-bit Arm but other
 * sources mention similar constraints for other architectures.
 */
FUNC tlsdesc_resolve , :
	ldr	x0, [x0, #8]
	ret
END_FUNC tlsdesc_resolve

