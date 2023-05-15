/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef GEN_ASM_DEFINES_H
#define GEN_ASM_DEFINES_H

#define DEFINES void __defines(void); void __defines(void)

#define DEFINE(def, val) \
	asm volatile("\n.ascii \"==>" #def " %c0 " #val "\"" : : "i" (val));

#endif /*GEN_ASM_DEFINES_H*/
