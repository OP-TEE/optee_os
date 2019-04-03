/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

	.macro FUNC_ALIGN align name colon
	.section .text.\name
	.global \name
	.type \name , %function
	.balign \align
	\name \colon
	.endm

	.macro FUNC name colon
	FUNC_ALIGN 4, \name, \colon
	.endm

	.macro DATA name colon
	.global \name
	.type \name , %object
	\name \colon
	.endm

	.macro LOCAL_FUNC_ALIGN align name colon
	.section .text.\name
	.type \name , %function
	.balign \align
	\name \colon
	.endm

	.macro LOCAL_FUNC name colon
	LOCAL_FUNC_ALIGN 4, \name, \colon
	.endm

	.macro LOCAL_DATA name colon
	.type \name , %object
	\name \colon
	.endm

	.macro END_DATA name
	.size \name , .-\name
	.endm

	.macro END_FUNC name
	.size \name , .-\name
	.endm
