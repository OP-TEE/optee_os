/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RUNTIMESUPPORT_H_
#define _RUNTIMESUPPORT_H_

// OPTEE provides simple versions of these headers
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

typedef uint64_t clock_t;

#ifndef XMEMCPY
#define XMEMCPY(pdest, psrc, size) memcpy((pdest), (psrc), (size))
#endif

#ifndef XMEMSET
#define XMEMSET(pdest, value, size) memset((pdest), (value), (size))
#endif

#ifndef XSTRLEN
#define XSTRLEN(str) strlen((str))
#endif

#ifndef XSTRNCPY
#define XSTRNCPY(str1,str2,n) strncpy((str1),(str2),(n))
#endif

#ifndef XSTRNCASECMP
int strncasecmp(const char *str1, const char *str2, size_t n);
#define XSTRNCASECMP(str1,str2,n) strncasecmp((str1),(str2),(n))
#endif

#ifndef XSTRNCMP
#define XSTRNCMP(str1,str2,n) strncmp((str1),(str2),(n))
#endif

#ifndef XMEMCMP
#define XMEMCMP(str1,str2,n) memcmp((str1),(str2),(n))
#endif

#undef  WC_NO_HASHDRBG
#define WC_NO_HASHDRBG

/* Bypass P-RNG and use only HW RNG */
extern int wolfRand(unsigned char* output, unsigned int sz);
#undef  CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK  wolfRand
#endif
