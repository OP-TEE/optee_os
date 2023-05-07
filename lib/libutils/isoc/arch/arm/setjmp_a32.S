/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 1994-2009  Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* This is a simple version of setjmp and longjmp.

   Nick Clifton, Cygnus Solutions, 13 June 1997.  */

/* ANSI concatenation macros.  */
#define CONCAT(a, b)  CONCAT2(a, b)
#define CONCAT2(a, b) a##b

#ifndef __USER_LABEL_PREFIX__
#error  __USER_LABEL_PREFIX__ not defined
#endif

#define SYM(x) CONCAT (__USER_LABEL_PREFIX__, x)

#ifdef __ELF__
#define TYPE(x) .type SYM(x),function
#define SIZE(x) .size SYM(x), . - SYM(x)
#else
#define TYPE(x)
#define SIZE(x)
#endif

	.section .note.GNU-stack,"",%progbits

/* Arm/Thumb interworking support:

   The interworking scheme expects functions to use a BX instruction
   to return control to their parent.  Since we need this code to work
   in both interworked and non-interworked environments as well as with
   older processors which do not have the BX instruction we do the 
   following:
	Test the return address.
	If the bottom bit is clear perform an "old style" function exit.
	(We know that we are in ARM mode and returning to an ARM mode caller).
	Otherwise use the BX instruction to perform the function exit.

   We know that we will never attempt to perform the BX instruction on 
   an older processor, because that kind of processor will never be 
   interworked, and a return address with the bottom bit set will never 
   be generated.

   In addition, we do not actually assemble the BX instruction as this would
   require us to tell the assembler that the processor is an ARM7TDMI and
   it would store this information in the binary.  We want this binary to be
   able to be linked with binaries compiled for older processors however, so
   we do not want such information stored there.  

   If we are running using the APCS-26 convention however, then we never
   test the bottom bit, because this is part of the processor status.  
   Instead we just do a normal return, since we know that we cannot be 
   returning to a Thumb caller - the Thumb does not support APCS-26.
	
   Function entry is much simpler.  If we are compiling for the Thumb we 
   just switch into ARM mode and then drop through into the rest of the
   function.  The function exit code will take care of the restore to
   Thumb mode.
   
   For Thumb-2 do everything in Thumb mode.  */

#if defined(__ARM_ARCH_6M__)
/* ARMv6-M has to be implemented in Thumb mode.  */

.thumb
.thumb_func
	.globl SYM (setjmp)
	TYPE (setjmp)
SYM (setjmp):
	/* Save registers in jump buffer.  */
	stmia	r0!, {r4, r5, r6, r7}
	mov	r1, r8
	mov	r2, r9
	mov	r3, r10
	mov	r4, fp
	mov	r5, sp
	mov	r6, lr
	stmia	r0!, {r1, r2, r3, r4, r5, r6}
	sub	r0, r0, #40
	/* Restore callee-saved low regs.  */
	ldmia	r0!, {r4, r5, r6, r7}
	/* Return zero.  */
	mov	r0, #0
	bx lr

.thumb_func
	.globl SYM (longjmp)
	TYPE (longjmp)
SYM (longjmp):
	/* Restore High regs.  */
	add	r0, r0, #16
	ldmia	r0!, {r2, r3, r4, r5, r6}
	mov	r8, r2
	mov	r9, r3
	mov	r10, r4
	mov	fp, r5
	mov	sp, r6
	ldmia	r0!, {r3} /* lr */
	/* Restore low regs.  */
	sub	r0, r0, #40
	ldmia	r0!, {r4, r5, r6, r7}
	/* Return the result argument, or 1 if it is zero.  */
	mov	r0, r1
	bne	1f
	mov	r0, #1
1:
	bx	r3

#else

#ifdef __APCS_26__
#define RET	movs		pc, lr
#elif defined(__thumb2__)
#define RET	bx lr
#else
#define RET	tst		lr, #1; \
	        moveq		pc, lr ; \
.word           0xe12fff1e	/* bx lr */
#endif

#ifdef __thumb2__
.macro COND where when 
	i\where	\when
.endm
#else
.macro COND where when 
.endm
#endif

#if defined(__thumb2__)
.syntax unified
.macro MODE
	.thumb
	.thumb_func
.endm
.macro PROLOGUE name
.endm

#elif defined(__thumb__)
#define	MODE		.thumb_func
.macro PROLOGUE name
	.code 16
	bx	pc
	nop	
	.code 32
SYM (.arm_start_of.\name):
.endm
#else /* Arm */
#define	MODE		.code 32
.macro PROLOGUE name
.endm
#endif
	
.macro FUNC_START name
	.text
	.align 2
	MODE
	.globl SYM (\name)
	TYPE (\name)
SYM (\name):
	PROLOGUE \name
.endm

.macro FUNC_END name
	RET
	SIZE (\name)
.endm
	
/* --------------------------------------------------------------------
                 int setjmp (jmp_buf); 
   -------------------------------------------------------------------- */
	
	FUNC_START setjmp

	/* Save all the callee-preserved registers into the jump buffer.  */
#ifdef __thumb2__
	mov		ip, sp
	stmea		a1!, { v1-v7, fp, ip, lr }
#else
	stmea		a1!, { v1-v7, fp, ip}
	str 		sp, [a1], #4
	str 		lr, [a1], #4
#endif
	
#if 0	/* Simulator does not cope with FP instructions yet.  */
#ifndef __SOFTFP__
	/* Save the floating point registers.  */
	sfmea		f4, 4, [a1]
#endif
#endif		

#ifdef CFG_FTRACE_SUPPORT
	stmdb		sp!, { lr }
	/*
	 * As ftrace is supported in ARM mode only, so hardcode jmp_buf
	 * offset used to save ftrace return index.
	 */
	add		a1, a1, #48
	bl		ftrace_setjmp
	ldmia		sp!, { lr }
#endif

	/* When setting up the jump buffer return 0.  */
	mov		a1, #0

	FUNC_END setjmp
	
/* --------------------------------------------------------------------
		volatile void longjmp (jmp_buf, int);
   -------------------------------------------------------------------- */
	
	FUNC_START longjmp

	/* If we have stack extension code it ought to be handled here.  */
	
#ifdef CFG_FTRACE_SUPPORT
	stmdb		sp!, { a1, a2, lr }
	/*
	 * As ftrace is supported in ARM mode only, so hardcode jmp_buf
	 * offset used to restore ftrace return stack.
	 */
	add		a1, a1, #92
	bl		ftrace_longjmp
	ldmia		sp!, { a1, a2, lr }
#endif

	/* Restore the registers, retrieving the state when setjmp() was called.  */
#ifdef __thumb2__
	ldmfd		a1!, { v1-v7, fp, ip, lr }
	mov		sp, ip
#else
	ldmfd		a1!, { v1-v7, fp, ip }
	ldr		sp, [a1], #4
	ldr 		lr, [a1], #4
#endif
	
#if 0	/* Simulator does not cope with FP instructions yet.  */
#ifndef __SOFTFP__
	/* Restore floating point registers as well.  */
	lfmfd		f4, 4, [a1]
#endif
#endif	
	/* Put the return value into the integer result register.
	   But if it is zero then return 1 instead.  */	
	movs		a1, a2
#ifdef __thumb2__
	it		eq
#endif
	moveq		a1, #1

	FUNC_END longjmp
#endif
