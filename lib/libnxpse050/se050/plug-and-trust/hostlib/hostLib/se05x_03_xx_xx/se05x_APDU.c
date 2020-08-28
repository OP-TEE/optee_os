/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <sm_types.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_SE05X

#ifdef FLOW_VERBOSE
#define VERBOSE_APDU_LOGS 1
#else
#define VERBOSE_APDU_LOGS 0
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif

#include "nxLog_hostLib.h"

/* TLV APIs */
#include "se05x_tlv.h"
/* Used constants */
#include "se05x_const.h"

#include "se05x_APDU.h"

/* Generated implementation */
#include "se05x_APDU_impl.h"

#if SSS_HAVE_SE05X_VER_GTE_04_04
#include "se05x_04_xx_APDU_impl.h"
#endif

smStatus_t Se05x_API_I2CM_Send(
    pSe05xSession_t session_ctx, const uint8_t *buffer, size_t bufferLen, uint8_t *result, size_t *presultLen)
{
    smStatus_t retStatus  = SM_NOT_OK;
    const tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_I2CM}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    uint8_t *pCmdbuf = &cmdbuf[0];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);

    /*tlvRet = TLVSET_Se05xSession("session identifier", &pCmdbuf, &cmdbufLen, kSE05x_TAG_SESSION_ID, session_ctx);
    if (0 != tlvRet) {
        goto cleanup;
    }*/
    tlvRet = TLVSET_u8buf("TLV Buffer", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, buffer, bufferLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);

    LOG_AU8_D(rspbuf, rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, result, presultLen);
        if (0 != tlvRet) { //Response check is skipped to be corrected.
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }
cleanup:
    return retStatus;
}
#endif // SSS_HAVE_SE05X

#ifdef __cplusplus
}
#endif
