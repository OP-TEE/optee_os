/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */

#if defined(__aarch64__)
#include <arm64_bti.S>
#endif

#if defined(__aarch64__) && ((defined(__KERNEL__) && defined(CFG_CORE_BTI)) || \
			     (!defined(__KERNEL__) && defined(CFG_TA_BTI)))
#define BTI(...) __VA_ARGS__
#else
#define BTI(...)
#endif

#if defined(CFG_UNWIND) && defined(__arm__)
#define UNWIND(...) __VA_ARGS__
#else
#define UNWIND(...)
#endif

	.macro FUNC name colon section=default align=4 _bti=default
	.ifc	\section\(),default
	.section .text.\name
	.else
	.section \section , "ax" , %progbits
	.endif
	.global \name
	.type \name , %function
	.balign \align
	\name \colon
UNWIND(	.fnstart)
	.ifc	\_bti\(),default
BTI(	bti	c)
	.endif
	.endm

	.macro LOCAL_FUNC name colon section=default align=4 _bti=default
	.ifc	\section\(),default
	.section .text.\name
	.else
	.section \section , "ax" , %progbits
	.endif
	.type \name , %function
	.balign \align
	\name \colon
UNWIND(	.fnstart)
	.ifc	\_bti\(),default
BTI(	bti	c)
	.endif
	.endm

	.macro WEAK_FUNC name colon section=default align=4 _bti=default
	.ifc	\section\(),default
	.section .text.\name
	.else
	.section \section , "ax" , %progbits
	.endif
	.weak \name
	.type \name , %function
	.balign \align
	\name \colon
UNWIND(	.fnstart)
	.ifc	\_bti\(),default
BTI(	bti	c)
	.endif
	.endm

	.macro END_FUNC name
UNWIND(	.fnend)
	.size \name , .-\name
	.endm

	.macro DATA name colon
	.global \name
	.type \name , %object
	\name \colon
	.endm

	.macro LOCAL_DATA name colon
	.type \name , %object
	\name \colon
	.endm

	.macro END_DATA name
	.size \name , .-\name
	.endm
