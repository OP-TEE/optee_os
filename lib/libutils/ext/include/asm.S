/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */

#if defined(CFG_UNWIND) && defined(__arm__)
#define UNWIND(...) __VA_ARGS__
#else
#define UNWIND(...)
#endif

	.macro FUNC name colon section=default align=4
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
	.endm

	.macro LOCAL_FUNC name colon section=default align=4
	.ifc	\section\(),default
	.section .text.\name
	.else
	.section \section , "ax" , %progbits
	.endif
	.type \name , %function
	.balign \align
	\name \colon
UNWIND(	.fnstart)
	.endm

	.macro WEAK_FUNC name colon section=default align=4
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
