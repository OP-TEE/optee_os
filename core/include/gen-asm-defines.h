/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef __GEN_ASM_DEFINES_H
#define __GEN_ASM_DEFINES_H

#define DEFINES void __defines(void); void __defines(void)

#define DEFINE(def, val) \
	asm volatile("\n.ascii \"==>" #def " %c0 " #val "\"" : : "i" (val));

#endif /*__GEN_ASM_DEFINES_H*/
