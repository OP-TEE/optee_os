/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_EX_INC_EX_SSS_H_
#define SSS_EX_INC_EX_SSS_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <fsl_sss_api.h>

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
#include <fsl_sscp_a71ch.h>
#endif
#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif
#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_apis.h>
#endif

#if SSS_HAVE_SSCP
#include <fsl_sss_sscp.h>
#endif

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

#if 0
typedef struct
{
    sss_session_t currentSession;

    sss_key_store_t ks;

    sss_sscp_session_t *sscp_session;
#if (SSS_HAVE_A71CH) || (SSS_HAVE_A71CH_SIM)
    sss_a71ch_key_store_t *a71ch_keystore;
#endif

    sscp_context_t sscp;
    sss_asymmetric_t asymVerifyCtx;
    sss_asymmetric_t asymm;
    sss_object_t keyPair;
    sss_object_t extPubkey;

    sss_object_t Device_Cert;
    sss_object_t Pubkey;
    sss_object_t interCaCert;
    sss_object_t interkeyPair;
    sss_object_t clientCert;
#if SSS_HAVE_APPLET_SE05X_IOT
    sss_session_t hostSession;
    sss_key_store_t hostKs;
    sss_object_t hostKey;
#endif
    sss_symmetric_t symm;
    sss_rng_context_t rng;
    sss_mac_t mac;

} sss_ex_ctx_t;

#endif

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
// extern const char *gszA71COMPortDefault;
// extern const char *gszA71SocketPortDefault;

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/* Entry point for each individual SSS API Based example */

#endif /* SSS_EX_INC_EX_SSS_H_ */
