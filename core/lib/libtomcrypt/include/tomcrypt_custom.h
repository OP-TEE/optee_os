/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2001-2007, Tom St Denis
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
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

#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_

#define LTC_NO_PROTOTYPES
#define LTC_SOURCE
#define LTC_NO_TABLES
// #define LTC_VERBOSE
#define LTC_NO_TEST

/* macros for various libc functions you can change for embedded targets */
#ifndef XMALLOC
   #ifdef malloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XMALLOC  malloc
#endif
#ifndef XREALLOC
   #ifdef realloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XREALLOC realloc
#endif
#ifndef XCALLOC
   #ifdef calloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XCALLOC  calloc
#endif
#ifndef XFREE
   #ifdef free
   #define LTC_NO_PROTOTYPES
   #endif
#define XFREE    free
#endif

#ifndef XMEMSET
   #ifdef memset
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMSET  memset
#endif
#ifndef XMEMCPY
   #ifdef memcpy
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCPY  memcpy
#endif
#ifndef XMEMCMP
   #ifdef memcmp 
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCMP  memcmp
#endif
#ifndef XMEM_NEQ
#include <string_ext.h>
#define XMEM_NEQ  buf_compare_ct
#endif
#ifndef XSTRCMP
   #ifdef strcmp
   #define LTC_NO_PROTOTYPES
   #endif
#define XSTRCMP strcmp
#endif

#ifndef XCLOCK
#define XCLOCK   clock
#endif
#ifndef XCLOCKS_PER_SEC
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
#endif

#ifndef XQSORT
   #ifdef qsort
   #define LTC_NO_PROTOTYPES
   #endif
#define XQSORT qsort
#endif

/* Easy button? */
#ifdef LTC_EASY
   #define LTC_NO_CIPHERS
   #define LTC_RIJNDAEL
   #define LTC_BLOWFISH
   #define LTC_DES
   #define LTC_CAST5
   
   #define LTC_NO_MODES
   #define LTC_ECB_MODE
   #define LTC_CBC_MODE
   #define LTC_CTR_MODE
   
   #define LTC_NO_HASHES
   #define LTC_SHA1
   #define LTC_SHA512
   #define LTC_SHA384
   #define LTC_SHA256
   #define LTC_SHA224


   #define LTC_NO_MACS
   #define LTC_HMAC
   #define LTC_OMAC
   #define LTC_CCM_MODE

   #define LTC_NO_PRNGS
   #define LTC_SPRNG
   #define LTC_DEVRANDOM
   #define LTC_TRY_URANDOM_FIRST
      
   #define LTC_NO_PK
   #define LTC_MRSA
   #define LTC_MECC
#endif   

/* Set LTC_ options based on OP-TEE configuration */

#define LTC_NO_CIPHERS

#ifdef CFG_CRYPTO_AES
   #define LTC_RIJNDAEL
#endif
#ifdef CFG_CRYPTO_DES
   #define LTC_DES
#endif

#define LTC_NO_MODES

#ifdef CFG_CRYPTO_ECB
   #define LTC_ECB_MODE
#endif
#if defined(CFG_CRYPTO_CBC) || defined(CFG_CRYPTO_CBC_MAC)
   #define LTC_CBC_MODE
#endif
#ifdef CFG_CRYPTO_CTR
   #define LTC_CTR_MODE
#endif
#ifdef CFG_CRYPTO_XTS
   #define LTC_XTS_MODE
#endif

#define LTC_NO_HASHES

#ifdef CFG_CRYPTO_MD5
#define LTC_MD5
#endif
#ifdef CFG_CRYPTO_SHA1
#define LTC_SHA1
#endif
#ifdef CFG_CRYPTO_SHA1_ARM32_CE
#define LTC_SHA1_ARM32_CE
#endif
#ifdef CFG_CRYPTO_SHA1_ARM64_CE
#define LTC_SHA1_ARM64_CE
#endif
#ifdef CFG_CRYPTO_SHA224
#define LTC_SHA224
#endif
#ifdef CFG_CRYPTO_SHA256
#define LTC_SHA256
#endif
#ifdef CFG_CRYPTO_SHA256_ARM32_CE
#define LTC_SHA256_ARM32_CE
#endif
#ifdef CFG_CRYPTO_SHA256_ARM64_CE
#define LTC_SHA256_ARM64_CE
#endif
#ifdef CFG_CRYPTO_SHA384
#define LTC_SHA384
#endif
#ifdef CFG_CRYPTO_SHA512
#define LTC_SHA512
#endif
#ifdef CFG_CRYPTO_SHA512_256
#define LTC_SHA512_256
#endif

#define LTC_NO_MACS

#ifdef CFG_CRYPTO_HMAC
   #define LTC_HMAC
#endif
#ifdef CFG_CRYPTO_CMAC
   #define LTC_OMAC
#endif
#ifdef CFG_CRYPTO_CCM
   #define LTC_CCM_MODE
#endif
#ifdef CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB
   #define LTC_GCM_MODE
#endif

#define LTC_NO_PK

#ifdef CFG_CRYPTO_RSA
   #define LTC_MRSA
#endif
#ifdef CFG_CRYPTO_DSA
   #define LTC_MDSA
#endif
#ifdef CFG_CRYPTO_DH
   #define LTC_MDH
#endif
#ifdef CFG_CRYPTO_ECC
   #define LTC_MECC

   /* use Shamir's trick for point mul (speeds up signature verification) */
   #define LTC_ECC_SHAMIR

   #if defined(TFM_LTC_DESC) && defined(LTC_MECC)
   #define LTC_MECC_ACCEL
   #endif

   /* do we want fixed point ECC */
   /* #define LTC_MECC_FP */

   /* Timing Resistant */
   #define LTC_ECC_TIMING_RESISTANT

   #define LTC_ECC192
   #define LTC_ECC224
   #define LTC_ECC256
   #define LTC_ECC384
   #define LTC_ECC521

   /* ECC 521 bits is the max supported key size */
   #define LTC_MAX_ECC 521
#endif

#define LTC_NO_PKCS

#if defined(CFG_CRYPTO_RSA) || defined(CFG_CRYPTO_DSA) || \
	    defined(CFG_CRYPTO_ECC)
   #define LTC_DER
#endif

/* Use small code where possible */
/* #define LTC_SMALL_CODE */

/* Enable self-test test vector checking */
#ifndef LTC_NO_TEST
   #define LTC_TEST
#endif

/* clean the stack of functions which put private information on stack */
/* #define LTC_CLEAN_STACK */

/* disable all file related functions */
#define LTC_NO_FILE

/* disable all forms of ASM */
/* #define LTC_NO_ASM */

/* disable FAST mode */
/* #define LTC_NO_FAST */

/* disable BSWAP on x86 */
/* #define LTC_NO_BSWAP */

/* ---> Symmetric Block Ciphers <--- */

#ifndef LTC_NO_CIPHERS

#define LTC_RIJNDAEL

/* LTC_DES includes EDE triple-LTC_DES */
#define LTC_DES

#endif

/* ---> Block Cipher Modes of Operation <--- */
#ifndef LTC_NO_MODES

#define LTC_CFB_MODE
#define LTC_OFB_MODE
#define LTC_ECB_MODE
#define LTC_CBC_MODE
#define LTC_CTR_MODE

/* F8 chaining mode */
#define LTC_F8_MODE

/* LRW mode */
#define LTC_LRW_MODE
#ifndef LTC_NO_TABLES
   /* like GCM mode this will enable 16 8x128 tables [64KB] that make
    * seeking very fast.  
    */
   #define LTC_LRW_TABLES
#endif

/* XTS mode */
#define LTC_XTS_MODE

#endif /* LTC_NO_MODES */

/* ---> One-Way Hash Functions <--- */
#ifndef LTC_NO_HASHES 

#define LTC_SHA512
#define LTC_SHA384
#define LTC_SHA256
#define LTC_SHA224
#define LTC_SHA1
#define LTC_MD5



#endif /* LTC_NO_HASHES */

/* ---> MAC functions <--- */
#ifndef LTC_NO_MACS

#define LTC_HMAC
#define LTC_OMAC
#define LTC_PMAC
#define LTC_XCBC


/* ---> Encrypt + Authenticate Modes <--- */

#define LTC_EAX_MODE
#if defined(LTC_EAX_MODE) && !(defined(LTC_CTR_MODE) && defined(LTC_OMAC))
   #error LTC_EAX_MODE requires CTR and LTC_OMAC mode
#endif

#define LTC_OCB_MODE
#define LTC_CCM_MODE
#define LTC_GCM_MODE

/* Use 64KiB tables */
#ifndef LTC_NO_TABLES
   #define LTC_GCM_TABLES 
#endif

/* USE SSE2? requires GCC works on x86_32 and x86_64*/
#ifdef LTC_GCM_TABLES
/* #define LTC_GCM_TABLES_SSE2 */
#endif

#endif /* LTC_NO_MACS */

/* Various tidbits of modern neatoness */
#define LTC_BASE64

/* --> Pseudo Random Number Generators <--- */
#ifndef LTC_NO_PRNGS

/* a PRNG that simply reads from an available system source */
#define LTC_SPRNG

/* The LTC_RC4 stream cipher */
#define LTC_RC4

/* Fortuna PRNG */
#define LTC_FORTUNA
/* reseed every N calls to the read function */
#define LTC_FORTUNA_WD    10
/* number of pools (4..32) can save a bit of ram by lowering the count */
#define LTC_FORTUNA_POOLS 32

/* the *nix style /dev/random device */
#define LTC_DEVRANDOM
/* try /dev/urandom before trying /dev/random */
#define LTC_TRY_URANDOM_FIRST

#endif /* LTC_NO_PRNGS */

/* ---> Public Key Crypto <--- */
#ifndef LTC_NO_PK

/* Include RSA support */
#define LTC_MRSA

/* Include Diffie-Hellman support */
/*
 * From libtomcrypt.org:
 *     DH vanished because nobody used it and it was a pain to support
 *     DH support rewritten by ST
 */
#define LTC_MDH

/* Include Katja (a Rabin variant like RSA) */
/* #define LTC_MKAT */

/* Digital Signature Algorithm */
#define LTC_MDSA

/* ECC */
#define LTC_MECC

/* use Shamir's trick for point mul (speeds up signature verification) */
#define LTC_ECC_SHAMIR

#if defined(TFM_LTC_DESC) && defined(LTC_MECC)
   #define LTC_MECC_ACCEL
#endif   

/* do we want fixed point ECC */
/* #define LTC_MECC_FP */

/* Timing Resistant? */
/* #define LTC_ECC_TIMING_RESISTANT */

#endif /* LTC_NO_PK */

/* in cases where you want ASN.1/DER functionality, but no
 * RSA, you can define this externally if 1024 is not enough
 */
#if defined(LTC_MRSA)
#define LTC_DER_MAX_PUBKEY_SIZE MAX_RSA_SIZE
#elif !defined(LTC_DER_MAX_PUBKEY_SIZE)
/* this includes DSA */
#define LTC_DER_MAX_PUBKEY_SIZE 1024
#endif

/* LTC_PKCS #1 (RSA) and #5 (Password Handling) stuff */
#ifndef LTC_NO_PKCS

#define LTC_PKCS_1
#define LTC_PKCS_5

/* Include ASN.1 DER (required by DSA/RSA) */
#define LTC_DER

#endif /* LTC_NO_PKCS */

/* cleanup */

#if defined(LTC_MECC) || defined(LTC_MRSA) || defined(LTC_MDSA) || \
	defined(MKATJA) || defined(LTC_MDH)
   /* Include the MPI functionality?  (required by the PK algorithms) */
   #define LTC_MPI
#endif

#ifdef LTC_MRSA
   #define LTC_PKCS_1
#endif   

#if defined(LTC_DER) && !defined(LTC_MPI)
   #error ASN.1 DER requires MPI functionality
#endif

#if (defined(LTC_MDSA) || defined(LTC_MRSA) || defined(LTC_MECC) || defined(MKATJA)) && !defined(LTC_DER)
   #error PK requires ASN.1 DER functionality, make sure LTC_DER is enabled
#endif


/* THREAD management */
#if defined(CFG_LTC_OPTEE_THREAD)

#include <kernel/mutex.h>

#define LTC_MUTEX_GLOBAL(x)   struct mutex x = MUTEX_INITIALIZER;
#define LTC_MUTEX_PROTO(x)    extern struct mutex x;
#define LTC_MUTEX_TYPE(x)     struct mutex x;
#define LTC_MUTEX_INIT(x)     mutex_init(x);
#define LTC_MUTEX_LOCK(x)     mutex_lock(x);
#define LTC_MUTEX_UNLOCK(x)   mutex_unlock(x);

#elif defined(LTC_PTHREAD)

#include <pthread.h>

#define LTC_MUTEX_GLOBAL(x)   pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#define LTC_MUTEX_PROTO(x)    extern pthread_mutex_t x;
#define LTC_MUTEX_TYPE(x)     pthread_mutex_t x;
#define LTC_MUTEX_INIT(x)     pthread_mutex_init(x, NULL);
#define LTC_MUTEX_LOCK(x)     pthread_mutex_lock(x);
#define LTC_MUTEX_UNLOCK(x)   pthread_mutex_unlock(x);

#else

/* default no functions */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)

#endif

/*
 * Here are a list of fixes required in libtomcrypt
 */

/*
 * From libtomcrypt.org:
 *     DH vanished because nobody used it and it was a pain to support
 * DH support was adapted from the master branch of libtomcrypt that can be
 * found at
 *     http://dev.openaos.org/browser/trunk/buildroot/gen7/buildroot/package/libtomcrypt/libtomcrypt-dh.patch
 * The original version was not taken as it makes use of static const array
 * containing base and prime, and did not include subprime and x-bits
 * constraints
 */
#define LTC_LINARO_FIX_DH

/*
 * XTS encryption / decryption does not update the tweak when successive
 * operations are performed.
 * Defining LTC_LINARO_FIX_XTS fixes this.
 */
#define LTC_LINARO_FIX_XTS

/* Debuggers */

/* define this if you use Valgrind, note: it CHANGES the way SOBER-128 and LTC_RC4 work (see the code) */
/* #define LTC_VALGRIND */

#if defined(ARM32) || defined(ARM64)
#define ENDIAN_LITTLE
#endif
#ifdef ARM32
#define ENDIAN_32BITWORD
#endif
#ifdef ARM64
#define ENDIAN_64BITWORD
#endif

#define LTC_ULONGXX_DEFINED
typedef uint32_t ulong32;
typedef uint64_t ulong64;
#define CONST64(x)	UINT64_C(x)

#endif



/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_custom.h,v $ */
/* $Revision: 1.73 $ */
/* $Date: 2007/05/12 14:37:41 $ */
