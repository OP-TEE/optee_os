/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_EX_INC_EX_SSS_AUTH_H_
#define SSS_EX_INC_EX_SSS_AUTH_H_

#include "ex_sss_boot.h"
#include "ex_sss_objid.h"
#include "ex_sss_scp03_keys.h"
#include "ex_scp03_puf.h"
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */

/* Used in examples and testing */
#define EX_SSS_AUTH_SE05X_UserID_AUTH_ID kEX_SSS_ObjID_UserID_Auth
#define EX_SSS_AUTH_SE05X_UserID_VALUE \
    {                                  \
        0xC0, 0x01, 0x02, 0x03, 0x04   \
    } /* COOL 234*/

#define EX_SSS_AUTH_SE05X_ECKEY_ECDSA_AUTH_ID kEX_SSS_objID_ECKEY_Auth

#define EX_SSS_AUTH_SE05X_APPLETSCP_AUTH_ID kEX_SSS_ObjID_APPLETSCP03_Auth

#define EX_SSS_AUTH_SE05X_NONE_AUTH_ID 0x00000000

#define EX_SSS_AUTH_SE05X_APPLETSCP_VALUE                                 \
    {                                                                     \
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, \
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F                                      \
    }

/* Use the Platform SCP03 keys from required OEF
 * See https://www.nxp.com/docs/en/application-note/AN12436.pdf
 */

#if EXTERNAL_CUSTOMER_BUILD_CONFIGURATION
#ifndef EX_SSS_AUTH_SE05X_KEY_ENC
#   define EX_SSS_AUTH_SE05X_KEY_ENC SSS_AUTH_SE050_DEVKIT_KEY_ENC
#endif
#ifndef EX_SSS_AUTH_SE05X_KEY_MAC
#   define EX_SSS_AUTH_SE05X_KEY_MAC SSS_AUTH_SE050_DEVKIT_KEY_MAC
#endif
#ifndef EX_SSS_AUTH_SE05X_KEY_DEK
#   define EX_SSS_AUTH_SE05X_KEY_DEK SSS_AUTH_SE050_DEVKIT_KEY_DEK
#endif
#else
/* Test / dummy keys */

#ifndef EX_SSS_AUTH_SE05X_KEY_ENC
#   define EX_SSS_AUTH_SE05X_KEY_ENC  \
    { 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01 }
#endif

#ifndef EX_SSS_AUTH_SE05X_KEY_MAC
#   define EX_SSS_AUTH_SE05X_KEY_MAC   \
    { 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02 }
#endif

#ifndef EX_SSS_AUTH_SE05X_KEY_DEK
#   define EX_SSS_AUTH_SE05X_KEY_DEK   \
    { 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x03 }
#endif

#endif


#define EX_SSS_AUTH_SE05X_KEY_VERSION_NO 0x0B

#define EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY                              \
    {                                                                     \
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,                   \
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,                   \
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,                   \
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,                   \
        0x01, 0x01, 0x04, 0x20,                                           \
        0x6D, 0x2F, 0x43, 0x2F, 0x8A, 0x2F, 0x45, 0xEC,                   \
        0xD5, 0x82, 0x84, 0x7E, 0xC0, 0x83, 0xBB, 0xEB,                   \
        0xC2, 0x3F, 0x1D, 0xF4, 0xF0, 0xDD, 0x2A, 0x6F,                   \
        0xB8, 0x1A, 0x24, 0xE7, 0xB6, 0xD5, 0x4C, 0x7F,                   \
        0xA1, 0x44, 0x03, 0x42, 0x00,                                     \
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,                   \
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,                   \
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,                   \
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,                   \
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,                   \
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,                   \
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,                   \
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,                   \
        0xC4                                                              \
    }

/* clang-format on */

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#endif /* SSS_EX_INC_EX_SSS_AUTH_H_ */
