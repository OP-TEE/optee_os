/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

	.macro FUNC name colon
	.section .text.\name
	.global \name
	.func \name
	.type \name , %function
	\name \colon
	.endm

	.macro DATA name colon
	.global \name
	.type \name , %object
	\name \colon
	.endm

	.macro LOCAL_FUNC name colon
	.section .text.\name
	.func \name
	.type \name , %function
	\name \colon
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
	.endfunc
	.endm
