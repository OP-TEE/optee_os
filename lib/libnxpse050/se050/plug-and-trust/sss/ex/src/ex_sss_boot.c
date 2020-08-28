/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot.c:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@appboot-top-eclipse_x86
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "ex_sss_boot.h"

#include <ex_sss.h>
#include <string.h>

#include "ex_sss_boot_int.h"
#include "nxLog_App.h"
#include "stdio.h"

#include "fsl_sss_lpc55s_apis.h"

#if SSS_HAVE_APPLET_SE05X_IOT
#include "se05x_APDU.h"
#endif

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

sss_status_t ex_sss_boot_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
    status = ex_sss_boot_a71ch_open(pCtx, portName);
#elif SSS_HAVE_A71CL || SSS_HAVE_SE050_L
    status = ex_sss_boot_a71cl_open(pCtx, portName);
#elif SSS_HAVE_APPLET_SE05X_IOT
    status = ex_sss_boot_se05x_open(pCtx, portName);
#elif SSS_HAVE_SE
    status = ex_sss_boot_se_open(pCtx, portName);
#elif SSS_HAVE_MBEDTLS
    status = ex_sss_boot_mbedtls_open(pCtx, portName);
#elif SSS_HAVE_OPENSSL
    status = ex_sss_boot_openssl_open(pCtx, portName);
#endif
    return status;
}

sss_status_t ex_sss_boot_factory_reset(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
    uint16_t ret;
    ret = HLSE_DbgReset();
    if (ret == HLSE_SW_OK)
        status = kStatus_SSS_Success;

#elif SSS_HAVE_A71CL || SSS_HAVE_SE050_L
    status = kStatus_SSS_Success;

#elif SSS_HAVE_APPLET_SE05X_IOT
    smStatus_t st;
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx->session;
    st                            = Se05x_API_DeleteAll_Iterative(&pSession->s_ctx);
    if (st == SW_OK)
        status = kStatus_SSS_Success;

#elif SSS_HAVE_MBEDTLS
    status = kStatus_SSS_Success;
#elif SSS_HAVE_OPENSSL
    status = kStatus_SSS_Success;
#else
    LOG_E("Select atleast one security subsystem");
#endif
    return status;
}

sss_status_t ex_sss_kestore_and_object_init(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status;
    status = sss_key_store_context_init(&pCtx->ks, &pCtx->session);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_context_init Failed...");
        goto cleanup;
    }

    status = sss_key_store_allocate(&pCtx->ks, __LINE__);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_allocate Failed...");
        goto cleanup;
    }

cleanup:
    return status;
}

#if ((SSS_HAVE_HOSTCRYPTO_ANY) && ((SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) || \
    (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)))
static void free_auth_objects(SE_Connect_Ctx_t *pConnectCtx)
{
    if (pConnectCtx->auth.authType == kSSS_AuthType_ID) {
        sss_host_key_object_free(pConnectCtx->auth.ctx.idobj.pObj);
    }

    if (pConnectCtx->auth.authType == kSSS_AuthType_SCP03 || pConnectCtx->auth.authType == kSSS_AuthType_AESKey) {
        NXSCP03_AuthCtx_t *pSC = &pConnectCtx->auth.ctx.scp03;
        sss_host_key_object_free(&pSC->pStatic_ctx->Enc);
        sss_host_key_object_free(&pSC->pStatic_ctx->Mac);
        sss_host_key_object_free(&pSC->pStatic_ctx->Dek);
        sss_host_key_object_free(&pSC->pDyn_ctx->Enc);
        sss_host_key_object_free(&pSC->pDyn_ctx->Mac);
        sss_host_key_object_free(&pSC->pDyn_ctx->Rmac);
    }

    if (pConnectCtx->auth.authType == kSSS_AuthType_ECKey) {
        SE05x_AuthCtx_ECKey_t *pEC = &pConnectCtx->auth.ctx.eckey;
        sss_host_key_object_free(&pEC->pStatic_ctx->HostEcdsaObj);
        sss_host_key_object_free(&pEC->pStatic_ctx->HostEcKeypair);
        sss_host_key_object_free(&pEC->pStatic_ctx->masterSec);
        sss_host_key_object_free(&pEC->pStatic_ctx->SeEcPubKey);
        sss_host_key_object_free(&pEC->pDyn_ctx->Enc);
        sss_host_key_object_free(&pEC->pDyn_ctx->Mac);
        sss_host_key_object_free(&pEC->pDyn_ctx->Rmac);
    }
}
#endif /* SSS_HAVE_HOSTCRYPTO_ANY */

void ex_sss_session_close(ex_sss_boot_ctx_t *pCtx)
{
#if SSS_HAVE_APPLET_SE05X_IOT || SSS_HAVE_SSCP
    if (pCtx->session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_session_close(&pCtx->session);
        sss_session_delete(&pCtx->session);
    }

#if SSS_HAVE_APPLET_SE05X_IOT
#if ((SSS_HAVE_HOSTCRYPTO_ANY) && ((SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) ||\
     (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) || \
     (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)))
    SE_Connect_Ctx_t *pConnectCtx = &pCtx->se05x_open_ctx;
    free_auth_objects(pConnectCtx);
#endif /* SSS_HAVE_HOSTCRYPTO_ANY */

    if (pCtx->pTunnel_ctx && pCtx->pTunnel_ctx->session) {
        if (pCtx->pTunnel_ctx->session->subsystem != kType_SSS_SubSystem_NONE) {
            sss_session_close(pCtx->pTunnel_ctx->session);
        }
    }

#if ((SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03) || (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03) || \
    (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03) || (SSS_HAVE_SE05X_AUTH_PLATFSCP03) ||         \
    (SSS_HAVE_SE05X_AUTH_AESKEY))
    {
        ex_SE05x_authCtx_t *pauth = &pCtx->ex_se05x_auth;
        sss_host_key_object_free(&pauth->scp03.ex_static.Enc);
        sss_host_key_object_free(&pauth->scp03.ex_static.Mac);
        sss_host_key_object_free(&pauth->scp03.ex_static.Dek);
        sss_host_key_object_free(&pauth->scp03.ex_dyn.Enc);
        sss_host_key_object_free(&pauth->scp03.ex_dyn.Mac);
        sss_host_key_object_free(&pauth->scp03.ex_dyn.Rmac);
    }
#elif (SSS_HAVE_SE05X_AUTH_USERID)
    sss_host_key_object_free(pCtx->se05x_open_ctx.auth.ctx.idobj.pObj);
#elif (SSS_HAVE_SE05X_AUTH_ECKEY)
    {
        ex_SE05x_authCtx_t *pauth = &pCtx->ex_se05x_auth;
        sss_host_key_object_free(&pauth->eckey.ex_static.HostEcdsaObj);
        sss_host_key_object_free(&pauth->eckey.ex_static.HostEcKeypair);
        sss_host_key_object_free(&pauth->eckey.ex_static.masterSec);
        sss_host_key_object_free(&pauth->eckey.ex_static.SeEcPubKey);
        sss_host_key_object_free(&pauth->eckey.ex_dyn.Enc);
        sss_host_key_object_free(&pauth->eckey.ex_dyn.Mac);
        sss_host_key_object_free(&pauth->eckey.ex_dyn.Rmac);
    }
#endif /* PF SCP */

#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#if SSS_HAVE_HOSTCRYPTO_ANY
    if (pCtx->host_ks.session != NULL) {
        sss_host_key_store_context_free(&pCtx->host_ks);
    }
    if (pCtx->host_session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_host_session_close(&pCtx->host_session);
    }
#endif // SSS_HAVE_HOSTCRYPTO_ANY
#endif

    if (pCtx->ks.session != NULL) {
        sss_key_store_context_free(&pCtx->ks);
    }
}

#if SSS_HAVE_HOSTCRYPTO_ANY
sss_status_t ex_sss_boot_open_host_session(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_APPLET_SE05X_IOT || SSS_HAVE_SSCP
    if (pCtx->host_ks.session == NULL) {
        status = sss_session_open(&pCtx->host_session, kType_SSS_Software, 0, kSSS_ConnectionType_Plain, NULL);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed to open mbedtls Session");
            return status;
        }

        status = sss_key_store_context_init(&pCtx->host_ks, &pCtx->host_session);
        if (kStatus_SSS_Success != status) {
            LOG_E("sss_key_store_context_init failed");
            return status;
        }
        status = sss_key_store_allocate(&pCtx->host_ks, __LINE__);
        if (kStatus_SSS_Success != status) {
            LOG_E("sss_key_store_allocate failed");
            return status;
        }
    }
#endif
    return status;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */

#ifdef __cplusplus
}
#endif
