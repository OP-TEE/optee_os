/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#ifndef GUARD_TEE_MATHAPI_H
#define GUARD_TEE_MATHAPI_H

#include <stddef.h>		/* for size_t */
#include <stdint.h>		/* for uint32_t and friends */
#include <stdbool.h>		/* for bool (!) */

/*************************************************************
 *
 *  MACRO DEFINITIONS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  How functions are exported
 *
 */
#define TEE_MATHAPI_EXPORT

/*
 * The modes for String Conversion
 */
#define TEE_STRING_MODE_HEX_UC MPA_STRING_MODE_HEX_UC
#define TEE_STRING_MODE_HEX_LC MPA_STRING_MODE_HEX_UC

/*------------------------------------------------------------
 *
 *  Define IN, OUT, INBUF and OUTBUF to keep format from the spec.
 *
 */
#define IN const
#define OUT
#define INOUT
#define INBUF const
#define OUTBUF

/*************************************************************
 *
 *  MEMORY ALLOCATION AND SIZE
 *
 *************************************************************/

/*
 * THIS IS THE MAXIMUM NUMBER OF BITS THAT THE LIBRARY SUPPORTS.
 * It defines the size of the scratch memory pool for the underlying
 * mpa library.
 */
#define TEE_MAX_NUMBER_OF_SUPPORTED_BITS 2048

/*************************************************************
 *
 * INITIALIZATION FUNCTIONS
 *
 *************************************************************/

/*
 * !!! This function must be called before you do anything else !!!
 *  NOTE: Not part of the spec
 */
TEE_MATHAPI_EXPORT void _TEE_MathAPI_Init(void);

/* this function generate a syscall to teecore for random number
 * generation, this is supplied to libmpa. Thus libmpa linked with user
 * TA can use this function to get random number.
 */
TEE_Result get_rng_array(void *buf, size_t blen);

#endif
