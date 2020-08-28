/*
* Copyright 2016,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _A71CH_CONST_H_
#define _A71CH_CONST_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_A71CH && (!(SSS_HAVE_A71CH_SIM))
#   define APPLET_NAME "a71ch" // 0x61.37.31.63.68
#   define APPLET_NAME_LEN (sizeof(APPLET_NAME) - 1)
#   define SE_NAME  "A71CH"
#endif
#if SSS_HAVE_LOOPBACK
#   define APPLET_NAME  \
    { 0xD2, 0x76, 0x00, 0x00,  0x85, 0x54, 0x65, 0x73, \
      0x74, 0x01, 0x01 } //echo applet
#   define APPLET_NAME_LEN (11)
#   define SE_NAME  "LoopBack"
#endif
#if SSS_HAVE_A71CL
#   define APPLET_NAME   \
  { 0xA0, 0x00, 0x00, 0x00,   0x41, 0x6C, 0x69, 0x59, \
    0x75, 0x6E, 0x2E, 0x49,   0x44, 0x32, 0x01}// "Ali Yun"
#   define APPLET_NAME_LEN (15)
#   define SE_NAME  "A71CL"
#endif

#if SSS_HAVE_SE050_L
#   define APPLET_NAME   \
{   0xA0, 0x00, 0x00, 0x00,   0x41, 0x6C, 0x69, 0x59, \
    0x75, 0x6E, 0x2E, 0x49,   0x44, 0x32 \
}// "Ali Yun"


#   define APPLET_NAME_LEN (14)
#   define SE_NAME  "SE050_L"
#endif

#if SSS_HAVE_A71CH_SIM
#   define APPLET_NAME \
        {0xa0, 0x00, 0x00, 0x03,     0x96, 0x54, 0x53, 0x00, \
         0x00, 0x00, 0x01, 0x03,     0x00, 0x00, 0x00, 0x00}
#   define APPLET_NAME_LEN (16)
#   define SE_NAME  "SE050:EAR:CH"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#   define APPLET_NAME \
        {0xa0, 0x00, 0x00, 0x03,     0x96, 0x54, 0x53, 0x00,  \
         0x00, 0x00, 0x01, 0x03,     0x00, 0x00, 0x00, 0x00}
#   define APPLET_NAME_LEN (16)

#   define SSD_NAME \
        { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03}
#endif

#if SSS_HAVE_SE05X_A
#   define SE_NAME  "SE050:A"
#endif
#if SSS_HAVE_SE05X_B
#   define SE_NAME  "SE050:B"
#endif
#if SSS_HAVE_SE05X_C
#   define SE_NAME  "SE050:C"
#endif

#define A71CH_KEY_PAIR_MAX_A    2 //!< Maximum amount of ECC key pairs that can be stored in A71CH (A device)
#define A71CH_PUBLIC_KEY_MAX_A  2 //!< Maximum amount of ECC public keys that can be stored in A71CH (A device)
#define A71CH_SYM_KEY_MAX_A     4 //!< Maximum amount of Symmetric keys that can be stored in A71CH (A device)
#define A71CH_KEY_PAIR_MAX_B    4 //!< Maximum amount of ECC key pairs that can be stored in A71CH (B device)
#define A71CH_PUBLIC_KEY_MAX_B  3 //!< Maximum amount of ECC public keys that can be stored in A71CH (B device)
#define A71CH_SYM_KEY_MAX_B     8 //!< Maximum amount of Symmetric keys that can be stored in A71CH (A device)
#define A71CH_COUNTER_MAX       2 //!< Maximum amount of monotonic counters that can be stored in A71CH (A&B)

// We cover two A71CH product variants that differ in the amount of credentials that can be stored.
// These two variants are referred to (in this example source code) as
// - TYPE_A (or simply A) - which is the device with lesser storage
// - TYPE_B (or simply B) - which is the device with more storage
// As the example source code depends on the amount of credentials that can be stored
// the ::A71CH_DEVICE_TYPE define must be used to select between either variant at compile time.
#define A71CH_DEVICE_TYPE_A (0x41)  //!< Symbolic constant to represent the Initial A71CH device
#define A71CH_DEVICE_TYPE_B (0x42)  //!< Synbolic constant to represent the A71CH device with more storage
#define A71CH_DEVICE_TYPE A71CH_DEVICE_TYPE_B //!< Indicate the credential storage capabilities of the A71CH


/** @def A71CH_KEY_PAIR_MAX
 * Maximum ECC Key Pairs in the Secure module */
/** @def A71CH_PUBLIC_KEY_MAX
 * Maximum ECC Public Keys in the Secure module */
/** @def A71CH_SYM_KEY_MAX
 * Maximum ECC Symmetric Keys in the Secure module */
/** @def A71CH_GP_STORAGE_SIZE
 * Maximum General Purpose Storage in the Secure module */

#if A71CH_DEVICE_TYPE == A71CH_DEVICE_TYPE_A
//!< Effective value used in examples
#   define A71CH_KEY_PAIR_MAX   A71CH_KEY_PAIR_MAX_A
#   define A71CH_PUBLIC_KEY_MAX A71CH_PUBLIC_KEY_MAX_A
#   define A71CH_SYM_KEY_MAX    A71CH_SYM_KEY_MAX_A
#   define A71CH_GP_STORAGE_SIZE A71CH_GP_STORAGE_SIZE_A
#else
#   define A71CH_KEY_PAIR_MAX   A71CH_KEY_PAIR_MAX_B
#   define A71CH_PUBLIC_KEY_MAX A71CH_PUBLIC_KEY_MAX_B
#   define A71CH_SYM_KEY_MAX    A71CH_SYM_KEY_MAX_B
#   define A71CH_GP_STORAGE_SIZE A71CH_GP_STORAGE_SIZE_B
#endif

#ifdef __cplusplus
}
#endif
#endif //_A71CHCONSTL_H_
