/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
