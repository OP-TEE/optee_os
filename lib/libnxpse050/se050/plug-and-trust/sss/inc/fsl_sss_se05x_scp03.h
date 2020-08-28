/*
* Copyright 2018-2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef FSL_SSS_SE05X_SCP03_H
#define FSL_SSS_SE05X_SCP03_H

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#ifdef __cplusplus
extern "C" {
#endif

#include "nxScp03_Const.h"
#include "nxScp03_Types.h"
#include "se05x_tlv.h"
#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif
#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_apis.h>
#endif

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */
/**
* To send and receive encrypted communication using SCP03
*/
sss_status_t nxScp03_AuthenticateChannel(pSe05xSession_t se05xSession, NXSCP03_AuthCtx_t *authScp03);

/**
* To send and receive encrypted communication using Fast SCP
*/
sss_status_t nxECKey_AuthenticateChannel(pSe05xSession_t se05xSession, SE05x_AuthCtx_ECKey_t *pAuthFScp);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* FSL_SSS_SE05X_SCP03_H */
