/*
 * Copyright 2018,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_EX_INC_EX_SSS_SCP03_KEYS_H_
#define SSS_EX_INC_EX_SSS_SCP03_KEYS_H_

#include "ex_sss_tp_scp03_keys.h"

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define EX_SSS_BOOT_SCP03_PATH_ENV "EX_SSS_BOOT_SCP03_PATH"

/* Modify based on platform */
#if defined(ANDROID)
/* Could be set to /data/vendor/secure_iot/ if sepolicies are in effect */
/* doc:start:android-scp03-path */
#define EX_SSS_SCP03_FILE_DIR "/data/vendor/SE05x/"
#define EX_SSS_SCP03_FILE_PATH EX_SSS_SCP03_FILE_DIR "plain_scp.txt"
/* doc:end:android-scp03-path */
#elif defined(__linux__)
/* doc:start:linux-scp03-path */
#define EX_SSS_SCP03_FILE_DIR "/tmp/SE05X/"
#define EX_SSS_SCP03_FILE_PATH EX_SSS_SCP03_FILE_DIR "plain_scp.txt"
/* doc:end:linux-scp03-path */
#elif defined(_MSC_VER)
/* doc:start:windows-scp03-path */
#define EX_SSS_SCP03_FILE_DIR "C:\\nxp\\SE05X\\"
#define EX_SSS_SCP03_FILE_PATH EX_SSS_SCP03_FILE_DIR "plain_scp.txt"
/* doc:end:windows-scp03-path */
#else
/* Not defined / avialable */
#endif

#ifdef EX_SSS_SCP03_FILE_PATH
sss_status_t scp03_keys_from_path(
    uint8_t *penc, size_t enc_len, uint8_t *pmac, size_t mac_len, uint8_t *pdek, size_t dek_len);
#endif

#define SSS_AUTH_SE050_OEF_0004A2D0_KEY_ENC                                                            \
    {                                                                                                  \
        0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x01 \
    }

#define SSS_AUTH_SE050_OEF_0004A2D0_KEY_MAC                                                            \
    {                                                                                                  \
        0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x02 \
    }

#define SSS_AUTH_SE050_OEF_0004A2D0_KEY_DEK                                                            \
    {                                                                                                  \
        0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x03 \
    }

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#endif /* SSS_EX_INC_EX_SSS_SCP03_KEYS_H_ */
