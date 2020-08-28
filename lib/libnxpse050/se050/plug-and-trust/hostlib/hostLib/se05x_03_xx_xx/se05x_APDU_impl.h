/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(NONSECURE_WORLD)
#include "veneer_printf_table.h"
#endif

#if defined(NONSECURE_WORLD)
#define NEWLINE() DbgConsole_Printf_NSE("\r\n")
#else
#define NEWLINE() printf("\r\n")
#endif

smStatus_t Se05x_API_CreateSession(
    pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CREATE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateSession []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("auth", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, authObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, sessionId, psessionIdLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ExchangeSessionData(pSe05xSession_t session_ctx, pSe05xPolicy_t policy)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_POLICY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    //    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ExchangeSessionData []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_Se05xPolicy("Policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_RefreshSession(pSe05xSession_t session_ctx, pSe05xPolicy_t policy)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_REFRESH}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "RefreshSession []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CloseSession(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_CLOSE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CloseSession []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);
    return retStatus;
}

smStatus_t Se05x_API_VerifySessionUserID(pSe05xSession_t session_ctx, const uint8_t *userId, size_t userIdLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SESSION_UserID}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "VerifySessionUserID []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("userId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, userId, userIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetLockState(pSe05xSession_t session_ctx, uint8_t lockIndicator, uint8_t lockState)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_TRANSPORT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetLockState []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U8("lock indicator", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, lockIndicator);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("lock state", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, lockState);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetPlatformSCPRequest(pSe05xSession_t session_ctx, SE05x_PlatformSCPRequest_t platformSCPRequest)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_SCP}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetPlatformSCPRequest []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_PlatformSCPRequest("platf scp req", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, platformSCPRequest);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetAppletFeatures(pSe05xSession_t session_ctx, pSe05xAppletFeatures_t appletVariant)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_VARIANT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetAppletFeatures []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_Variant(&pCmdbuf, &cmdbufLen, kSE05x_TAG_1, appletVariant);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteECKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, kSE05x_P1_EC | key_part, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteECKey []");
#endif /* VERBOSE_APDU_LOGS */
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_FAILURE))
    {
        tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    tlvRet = TLVSET_MaxAttemps("maxAttempt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_MAX_ATTEMPTS, maxAttempt);
    if (0 != tlvRet) {
        goto cleanup;
    }
#if SSS_HAVE_SE05X_VER_GTE_05_08
    /* Tag policy Check is not applicable for Generate key */
    if (((privKey != NULL) && (privKeyLen != 0))
        || ((pubKey != NULL) && (pubKeyLen != 0)))
    {
        if ((policy != NULL) && (policy->object_exist == kSE05x_Result_SUCCESS))
        {
            tlvRet = TLVSET_Se05xPolicy("check policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
    }
#endif
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECCurve("curveID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("privKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, privKey, privKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("pubKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, pubKey, pubKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteRSAKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t size,
    const uint8_t *p,
    size_t pLen,
    const uint8_t *q,
    size_t qLen,
    const uint8_t *dp,
    size_t dpLen,
    const uint8_t *dq,
    size_t dqLen,
    const uint8_t *qInv,
    size_t qInvLen,
    const uint8_t *pubExp,
    size_t pubExpLen,
    const uint8_t *priv,
    size_t privLen,
    const uint8_t *pubMod,
    size_t pubModLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part,
    const SE05x_RSAKeyFormat_t rsa_format)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, kSE05x_P1_RSA | key_part, rsa_format}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteRSAKey []");
#endif /* VERBOSE_APDU_LOGS */
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_FAILURE))
    {
        tlvRet = TLVSET_Se05xPolicy("To be Checked(last 3 not pdf)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#if SSS_HAVE_SE05X_VER_GTE_05_08
    /* Tag policy Check is not applicable for Generate key */
    if (((p != NULL)&&(pLen != 0)) ||
        ((pubExp != NULL) && (pubExpLen != 0)) ||
        ((priv != NULL) && (privLen != 0)))
    {
        if ((policy != NULL) && (policy->object_exist == kSE05x_Result_SUCCESS))
        {
            tlvRet = TLVSET_Se05xPolicy("check policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
    }
#endif
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("size in bits", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, size);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("p", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, p, pLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("q", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, q, qLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("dp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, dp, dpLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("dq", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, dq, dqLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("qnv", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, qInv, qInvLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("public exp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_8, pubExp, pubExpLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("priv", &pCmdbuf, &cmdbufLen, kSE05x_TAG_9, priv, privLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional_ByteShift("public mod", &pCmdbuf, &cmdbufLen, kSE05x_TAG_10, pubMod, pubModLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteSymmKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_KeyID_t kekID,
    const uint8_t *keyValue,
    size_t keyValueLen,
    const SE05x_INS_t ins_type,
    const SE05x_SymmKeyType_t type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE | ins_type, type, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteSymmKey []");
#endif /* VERBOSE_APDU_LOGS */
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_FAILURE))
    {
        tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    tlvRet = TLVSET_MaxAttemps("maxAttempt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_MAX_ATTEMPTS, maxAttempt);
    if (0 != tlvRet) {
        goto cleanup;
    }
#if SSS_HAVE_SE05X_VER_GTE_05_08
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_SUCCESS))
    {
        tlvRet = TLVSET_Se05xPolicy("check policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#endif
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_KeyID("KEK id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, kekID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("key value", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, keyValue, keyValueLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteBinary(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_BINARY, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteBinary []");
#endif /* VERBOSE_APDU_LOGS */
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_FAILURE))
    {
        tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#if SSS_HAVE_SE05X_VER_GTE_05_08
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_SUCCESS))
    {
        tlvRet = TLVSET_Se05xPolicy("check policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#endif
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("input data", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    const uint8_t *userId,
    size_t userIdLen,
    const SE05x_AttestationType_t attestation_type)
{
    smStatus_t retStatus = SM_NOT_OK;
    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;
    tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_WRITE | attestation_type, kSE05x_P1_UserID, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WriteUserID []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_MaxAttemps("maxAttempt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_MAX_ATTEMPTS, maxAttempt);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("userId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, userId, userIdLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateCounter(pSe05xSession_t session_ctx, pSe05xPolicy_t policy, uint32_t objectID, uint16_t size)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_COUNTER, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "Se05x_API_CreateCounter []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    if (size != 0) {
        tlvRet = TLVSET_U16("size", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, size);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }

    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetCounterValue(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t size, uint64_t value)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_COUNTER, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetCounterValue []");
#endif /* VERBOSE_APDU_LOGS */

    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    if ((size > 0) && (size <= 8)) {
        if (value != 0) {
            tlvRet = TLVSET_U64_SIZE("value", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, value, size);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
    }
    else {
        LOG_E("Wrong size provided");
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_IncCounter(pSe05xSession_t session_ctx, uint32_t objectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_COUNTER, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(objectID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "IncCounter []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_WritePCR(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t pcrID,
    const uint8_t *initialValue,
    size_t initialValueLen,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_PCR, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;

    if (Se05x_IsInValidRangeOfUID(pcrID))
        return SM_NOT_OK;

#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "WritePCR []");
#endif /* VERBOSE_APDU_LOGS */
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_FAILURE))
    {
        tlvRet = TLVSET_Se05xPolicy("policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#if SSS_HAVE_SE05X_VER_GTE_05_08
    if ((policy != NULL) && (policy->object_exist == kSE05x_Result_SUCCESS))
    {
        tlvRet = TLVSET_Se05xPolicy("check policy", &pCmdbuf, &cmdbufLen, kSE05x_TAG_POLICY_CHECK, policy);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
#endif
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, pcrID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("initialValue", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, initialValue, initialValueLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ImportObject(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAKeyComponent_t rsaKeyComp,
    const uint8_t *serializedObject,
    size_t serializedObjectLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_DEFAULT, kSE05x_P2_IMPORT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ImportObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    if (rsaKeyComp != kSE05x_RSAKeyComponent_NA) {
        tlvRet = TLVSET_RSAKeyComponent("rsaKeyComp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaKeyComp);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    tlvRet = TLVSET_u8bufOptional(
        "serializedObject", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, serializedObject, serializedObjectLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ImportExternalObject(pSe05xSession_t session_ctx,
    const uint8_t *ECKeydata,
    size_t ECKeydataLen,
    const uint8_t *ECAuthKeyID,
    size_t ECAuthKeyIDLen,
    const uint8_t *serializedObject,
    size_t serializedObjectLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, 0x06, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ImportExternalObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8buf("AuthData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_IMPORT_AUTH_DATA, ECKeydata, ECKeydataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("AuthID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_IMPORT_AUTH_KEY_ID, ECAuthKeyID, ECAuthKeyIDLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional(
        "serializedObject", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, serializedObject, serializedObjectLen);

    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadObject(
    pSe05xSession_t session_ctx, uint32_t objectID, uint16_t offset, uint16_t length, uint8_t *data, size_t *pdataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadObject_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *data,
    size_t *pdataLen,
    uint8_t *attribute,
    size_t *pattributeLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *outrandom,
    size_t *poutrandomLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ_With_Attestation, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadObject_W_Attst []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("attestID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, attestID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_AttestationAlgo("attestAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, attestAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, random, randomLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_2, attribute, pattributeLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_TimeStamp(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_3, ptimeStamp); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_4, outrandom, poutrandomLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_5, chipId, pchipIdLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_6, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadRSA(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    SE05x_RSAPubKeyComp_t rsa_key_comp,
    uint8_t *data,
    size_t *pdataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadRSA []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSAPubKeyComp("rsa_key_comp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, rsa_key_comp);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadRSA_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    SE05x_RSAPubKeyComp_t rsa_key_comp,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *data,
    size_t *pdataLen,
    uint8_t *attribute,
    size_t *pattributeLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *outrandom,
    size_t *poutrandomLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ_With_Attestation, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadRSA_W_Attst []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, offset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16Optional("length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, length);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSAPubKeyComp("rsa_key_comp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, rsa_key_comp);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("attestID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, attestID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_AttestationAlgo("attestAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, attestAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, random, randomLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_2, attribute, pattributeLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_TimeStamp(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_3, ptimeStamp); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_4, outrandom, poutrandomLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_5, chipId, pchipIdLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_6, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ExportObject(
    pSe05xSession_t session_ctx, uint32_t objectID, SE05x_RSAKeyComponent_t rsaKeyComp, uint8_t *data, size_t *pdataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_EXPORT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ExportObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSAKeyComponent("rsaKeyComp", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaKeyComp);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, data, pdataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadType(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_SecureObjectType_t *ptype,
    uint8_t *pisTransient,
    const SE05x_AttestationType_t attestation_type)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ | attestation_type, kSE05x_P1_DEFAULT, kSE05x_P2_TYPE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadType []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_SecureObjectType(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, ptype); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_2, pisTransient); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_SIZE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadSize []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U16(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, psize); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
    uint16_t outputOffset,
    uint8_t filter,
    uint8_t *pmore,
    uint8_t *idlist,
    size_t *pidlistLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_LIST}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadIDList []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U16("output offset", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, outputOffset);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("filter", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, filter);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pmore); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf,
            &rspIndex,
            rspbufLen,
            kSE05x_TAG_2,
            idlist,
            pidlistLen); /* Byte array containing 4-byte identifiers */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CheckObjectExists(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_EXIST}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CheckObjectExists []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteSecureObject(pSe05xSession_t session_ctx, uint32_t objectID)
{
    smStatus_t retStatus = SM_NOT_OK;

    tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_DELETE_OBJECT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DeleteSecureObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CURVE, kSE05x_P2_CREATE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateECCurve []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_SetECCurveParam(pSe05xSession_t session_ctx,
    SE05x_ECCurve_t curveID,
    SE05x_ECCurveParam_t ecCurveParam,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CURVE, kSE05x_P2_PARAM}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "SetECCurveParam []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECCurveParam("ecCurveParam", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecCurveParam);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetECCurveId(pSe05xSession_t session_ctx, uint32_t objectID, uint8_t *pcurveId)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CURVE, kSE05x_P2_ID}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetECCurveId []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("object id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pcurveId); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadECCurveList(pSe05xSession_t session_ctx, uint8_t *curveList, size_t *pcurveListLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CURVE, kSE05x_P2_LIST}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadECCurveList []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, curveList, pcurveListLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_CURVE, kSE05x_P2_DELETE_OBJECT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DeleteECCurve []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_ECCurve("curve id", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, curveID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CreateCryptoObject(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    SE05x_CryptoContext_t cryptoContext,
    SE05x_CryptoModeSubType_t subtype)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_WRITE, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_DEFAULT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CreateCryptoObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoContext("cryptoContext", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoContext);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoModeSubType(
        "1-byte Crypto Object subtype, either from DigestMode, CipherMode or MACAlgo (depending on TAG_2).",
        &pCmdbuf,
        &cmdbufLen,
        kSE05x_TAG_3,
        subtype);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ReadCryptoObjectList(pSe05xSession_t session_ctx, uint8_t *idlist, size_t *pidlistLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_READ, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_LIST}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ReadCryptoObjectList []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet =
            tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, idlist, pidlistLen); /* If more ids are present */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteCryptoObject(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_CRYPTO_OBJ, kSE05x_P2_DELETE_OBJECT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DeleteCryptoObject []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ECDSASign []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECSignatureAlgo("ecSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_EdDSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "EdDSASign []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_EDSignatureAlgo("edSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, edSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDAASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECDAASignatureAlgo_t ecdaaSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *randomData,
    size_t randomDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ECDAASign []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECDAASignatureAlgo("ecdaaSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecdaaSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("randomData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, randomData, randomDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_VERIFY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ECDSAVerify []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_ECSignatureAlgo("ecSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, ecSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_EdDSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_VERIFY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "EdDSAVerify []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_EDSignatureAlgo("edSignAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, edSignAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_ECDHGenerateSharedSecret(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    uint8_t *sharedSecret,
    size_t *psharedSecretLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_EC, kSE05x_P2_DH}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "ECDHGenerateSharedSecret []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("pubKey", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, pubKey, pubKeyLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, sharedSecret, psharedSecretLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_RSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSASignatureAlgo_t rsaSigningAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "RSASign []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSASignatureAlgo("rsaSigningAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaSigningAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_RSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSASignatureAlgo_t rsaSigningAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_VERIFY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "RSAVerify []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSASignatureAlgo("rsaSigningAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaSigningAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("signature", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, signature, signatureLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_Result(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_RSAEncrypt(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *encryptedData,
    size_t *pencryptedDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_RSA, kSE05x_P2_ENCRYPT_ONESHOT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "RSAEncrypt []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSAEncryptionAlgo("rsaEncryptionAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaEncryptionAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, encryptedData, pencryptedDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_RSADecrypt(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *decryptedData,
    size_t *pdecryptedDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_RSA, kSE05x_P2_DECRYPT_ONESHOT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "RSADecrypt []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_RSAEncryptionAlgo("rsaEncryptionAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, rsaEncryptionAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, decryptedData, pdecryptedDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CipherInit(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *IV,
    size_t IVLen,
    const SE05x_Cipher_Oper_t operation)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_CIPHER, operation}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CipherInit []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("IV", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, IV, IVLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CipherUpdate(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_CIPHER, kSE05x_P2_UPDATE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CipherUpdate []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CipherFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_CIPHER, kSE05x_P2_FINAL}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CipherFinal []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_CipherOneShot(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CipherMode_t cipherMode,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *IV,
    size_t IVLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_Cipher_Oper_OneShot_t operation)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_CIPHER, operation}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "CipherOneShot []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CipherMode("cipherMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cipherMode);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("IV", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, IV, IVLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_MACInit(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const SE05x_Mac_Oper_t mac_oper)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_MAC, mac_oper}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "MACInit []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_MACUpdate(
    pSe05xSession_t session_ctx, const uint8_t *inputData, size_t inputDataLen, SE05x_CryptoObjectID_t cryptoObjectID)
{
    smStatus_t retStatus = SM_NOT_OK;

    tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_MAC, kSE05x_P2_UPDATE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "MACUpdate []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_MACFinal(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *macValidateData,
    size_t macValidateDataLen,
    uint8_t *macValue,
    size_t *pmacValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_MAC, kSE05x_P2_FINAL}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "MACFinal []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional(
        "macValidateData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, macValidateData, macValidateDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, macValue, pmacValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_MACOneShot_G(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t macOperation,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *macValue,
    size_t *pmacValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_MAC, kSE05x_P2_GENERATE_ONESHOT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "MACOneShot_G []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("macOperation", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, macOperation);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, macValue, pmacValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_MACOneShot_V(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t macOperation,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *MAC,
    size_t MACLen,
    uint8_t *macValue,
    size_t *pmacValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_MAC, kSE05x_P2_VALIDATE_ONESHOT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "MACOneShot_V []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("macOperation", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, macOperation);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional(
        "MAC to verify (when P2=P2_VALIDATE_ONESHOT)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, MAC, MACLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, macValue, pmacValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_HKDF(pSe05xSession_t session_ctx,
    uint32_t hmacID,
    SE05x_DigestMode_t digestMode,
    const uint8_t *salt,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    uint16_t deriveDataLen,
    uint8_t *hkdfOuput,
    size_t *phkdfOuputLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_HKDF}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "HKDF []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("hmacID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, hmacID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_DigestMode("digestMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, digestMode);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("salt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, salt, saltLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("info", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, info, infoLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16("2-byte requested length (L)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, deriveDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, hkdfOuput, phkdfOuputLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_HKDF_Extended(pSe05xSession_t session_ctx,
    uint32_t hmacID,
    SE05x_DigestMode_t digestMode,
    SE05x_HkdfMode_t hkdfMode,
    const uint8_t *salt,
    size_t saltLen,
    uint32_t saltID,
    const uint8_t *info,
    size_t infoLen,
    uint32_t derivedKeyID,
    uint16_t deriveDataLen,
    uint8_t *hkdfOuput,
    size_t *phkdfOuputLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_HKDF}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
    hdr.hdr[3]       = (hkdfMode == kSE05x_HkdfMode_ExpandOnly ? kSE05x_P2_HKDF_EXPAND_ONLY : kSE05x_P2_HKDF);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "HKDF []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("hmacID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, hmacID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_DigestMode("digestMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, digestMode);
    if (0 != tlvRet) {
        goto cleanup;
    }
    if ((salt != NULL) && (hkdfMode != kSE05x_HkdfMode_ExpandOnly)) {
        tlvRet = TLVSET_u8bufOptional("salt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, salt, saltLen);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    tlvRet = TLVSET_u8bufOptional("info", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, info, infoLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16("2-byte requested length (L)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, deriveDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    // Warning: TAGS must be in numerical order, so this cannot be the else statement of (salt != null)
    if ((salt == NULL) && (hkdfMode != kSE05x_HkdfMode_ExpandOnly)) {
        tlvRet = TLVSET_U32("saltID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_6, saltID);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    if (hkdfOuput == NULL) {
        tlvRet = TLVSET_U32("derivedKeyID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, derivedKeyID);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        if (hkdfOuput == NULL) {
            retStatus = SM_NOT_OK;
            if (2 == rspbufLen) {
                retStatus = (rspbuf[0] << 8) | (rspbuf[1]);
            }
        }
        else {
            retStatus       = SM_NOT_OK;
            size_t rspIndex = 0;
            tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, hkdfOuput, phkdfOuputLen); /*  */
            if (0 != tlvRet) {
                goto cleanup;
            }
            if ((rspIndex + 2) == rspbufLen) {
                retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
            }
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_PBKDF2(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *salt,
    size_t saltLen,
    uint16_t count,
    uint16_t requestedLen,
    uint8_t *derivedSessionKey,
    size_t *pderivedSessionKeyLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_PBKDF}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "PBKDF2 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32(
        "4-byte password identifier (object type must be HMACKey)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("salt", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, salt, saltLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16("count", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, count);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16("requestedLen", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, requestedLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet =
            tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, derivedSessionKey, pderivedSessionKeyLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFDiversifyKey(pSe05xSession_t session_ctx,
    uint32_t masterKeyID,
    uint32_t diversifiedKeyID,
    const uint8_t *divInputData,
    size_t divInputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_DIVERSIFY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFDiversifyKey []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("masterKeyID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, masterKeyID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("diversifiedKeyID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, diversifiedKeyID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("divInputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, divInputData, divInputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFAuthenticateFirstPart1(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_AUTH_FIRST_PART1}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFAuthenticateFirstPart1 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFAuthenticateNonFirstPart1(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_AUTH_NONFIRST_PART1}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFAuthenticateFirstPart1 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFAuthenticateFirstPart2(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_AUTH_FIRST_PART2}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFAuthenticateFirstPart2 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFAuthenticateNonFirstPart2(
    pSe05xSession_t session_ctx, const uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_AUTH_NONFIRST_PART2}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFAuthenticateNonFirstPart2 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFDumpSessionKeys(pSe05xSession_t session_ctx, uint8_t *sessionData, size_t *psessionDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_DUMP_KEY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFDumpSessionKeys []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf,
            &rspIndex,
            rspbufLen,
            kSE05x_TAG_1,
            sessionData,
            psessionDataLen); /* 38 bytes: KeyID.SesAuthENCKey || KeyID.SesAuthMACKey || TI || Cmd-Ctr */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFChangeKeyPart1(pSe05xSession_t session_ctx,
    uint32_t oldObjectID,
    uint32_t newObjectID,
    uint8_t keySetNr,
    uint8_t keyNoDESFire,
    uint8_t keyVer,
    uint8_t *KeyData,
    size_t *pKeyDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_CHANGE_KEY_PART1}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFChangeKeyPart1 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_KeyID("oldObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, oldObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("newObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, newObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("keySetNr", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, keySetNr);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("keyNoDESFire", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, keyNoDESFire);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("keyVer", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, keyVer);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, KeyData, pKeyDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFChangeKeyPart2(pSe05xSession_t session_ctx, const uint8_t *MAC, size_t MACLen, uint8_t *presult)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_CHANGE_KEY_PART2}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFChangeKeyPart2 []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("MAC", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, MAC, MACLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, presult); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DFKillAuthentication(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_KILL_AUTH}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DFKillAuthentication []");
#endif /* VERBOSE_APDU_LOGS */

    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

    return retStatus;
}

smStatus_t Se05x_API_TLSGenerateRandom(pSe05xSession_t session_ctx, uint8_t *randomValue, size_t *prandomValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_TLS, kSE05x_P2_RANDOM}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "TLSGenerateRandom []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, randomValue, prandomValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_TLSCalculatePreMasterSecret(pSe05xSession_t session_ctx,
    uint32_t keyPairId,
    uint32_t pskId,
    uint32_t hmacKeyId,
    const uint8_t *inputData,
    size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_TLS, kSE05x_P2_TLS_PMS}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "TLSCalculatePreMasterSecret []");
#endif /* VERBOSE_APDU_LOGS */
    if (pskId != 0) {
        tlvRet = TLVSET_U32("pskId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, pskId);
        if (0 != tlvRet) {
            goto cleanup;
        }
    }
    tlvRet = TLVSET_U32("keyPairId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, keyPairId);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("hmacKeyId", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, hmacKeyId);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_TLSPerformPRF(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t digestAlgo,
    const uint8_t *label,
    size_t labelLen,
    const uint8_t *random,
    size_t randomLen,
    uint16_t reqLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_TLSPerformPRFType_t tlsprf)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_TLS, tlsprf}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "TLSPerformPRF []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U32("objectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, objectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("digestAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, digestAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("Label (1 to 64 bytes)", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, label, labelLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("32-byte random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_4, random, randomLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U16("2-byte requested length", &pCmdbuf, &cmdbufLen, kSE05x_TAG_5, reqLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, outputData, poutputDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_I2CM_ExecuteCommandSet(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint32_t attestationID,
    uint8_t attestationAlgo,
    uint8_t *response,
    size_t *presponseLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *freshness,
    size_t *pfreshnessLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen,
    uint8_t *randomAttst,
    size_t randomAttstLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_I2CM_Attestation, kSE05x_P1_DEFAULT, kSE05x_P2_I2CM}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "I2CM_ExecuteCommandSet []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_u8bufOptional("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U32("attestationID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, attestationID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_U8("attestationAlgo", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, attestationAlgo);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8bufOptional("freshness random", &pCmdbuf, &cmdbufLen, kSE05x_TAG_7, randomAttst, randomAttstLen);
    if (0 != tlvRet) {
        goto cleanup;
    }

    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, response, presponseLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_TimeStamp(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_3, ptimeStamp); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_4, freshness, pfreshnessLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_5, chipId, pchipIdLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_6, signature, psignatureLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestInit(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_INIT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DigestInit []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestUpdate(
    pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID, const uint8_t *inputData, size_t inputDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_UPDATE}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DigestUpdate []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmacValue,
    size_t *pcmacValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_FINAL}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DigestFinal []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_CryptoObjectID("cryptoObjectID", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, cryptoObjectID);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_3, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, cmacValue, pcmacValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DigestOneShot(pSe05xSession_t session_ctx,
    uint8_t digestMode,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *hashValue,
    size_t *phashValueLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_CRYPTO, kSE05x_P1_DEFAULT, kSE05x_P2_ONESHOT}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DigestOneShot []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U8("digestMode", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, digestMode);
    if (0 != tlvRet) {
        goto cleanup;
    }
    tlvRet = TLVSET_u8buf("inputData", &pCmdbuf, &cmdbufLen, kSE05x_TAG_2, inputData, inputDataLen);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, hashValue, phashValueLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetVersion(pSe05xSession_t session_ctx, uint8_t *pappletVersion, size_t *appletVersionLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_VERSION}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetVersion []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pappletVersion, appletVersionLen); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetTimestamp(pSe05xSession_t session_ctx, SE05x_TimeStamp_t *ptimeStamp)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_TIME}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetTimestamp []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTxRx_s_Case2(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_TimeStamp(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, ptimeStamp); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetFreeMemory(pSe05xSession_t session_ctx, SE05x_MemoryType_t memoryType, uint16_t *pfreeMem)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_MEMORY}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetFreeMemory []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_MemoryType("memoryType", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, memoryType);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_U16(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, pfreeMem); /* - */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_GetRandom(pSe05xSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_RANDOM}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
    uint8_t *pCmdbuf = &cmdbuf[0];
    int tlvRet       = 0;
    uint8_t rspbuf[SE05X_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = ARRAY_SIZE(rspbuf);
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "GetRandom []");
#endif /* VERBOSE_APDU_LOGS */
    tlvRet = TLVSET_U16("size", &pCmdbuf, &cmdbufLen, kSE05x_TAG_1, size);
    if (0 != tlvRet) {
        goto cleanup;
    }
    retStatus = DoAPDUTxRx_s_Case4_ext(session_ctx, &hdr, cmdbuf, cmdbufLen, rspbuf, &rspbufLen);
    if (retStatus == SM_OK) {
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        tlvRet          = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, kSE05x_TAG_1, randomData, prandomDataLen); /*  */
        if (0 != tlvRet) {
            goto cleanup;
        }
        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

cleanup:
    return retStatus;
}

smStatus_t Se05x_API_DeleteAll(pSe05xSession_t session_ctx)
{
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_DELETE_ALL}};
    uint8_t cmdbuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t cmdbufLen = 0;
#if VERBOSE_APDU_LOGS
    NEWLINE();
    nLog("APDU", NX_LEVEL_DEBUG, "DeleteAll []");
#endif /* VERBOSE_APDU_LOGS */
    retStatus = DoAPDUTx_s_Case3(session_ctx, &hdr, cmdbuf, cmdbufLen);
    return retStatus;
}
