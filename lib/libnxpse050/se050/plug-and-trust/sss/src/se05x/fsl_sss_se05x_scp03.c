/*
* Copyright 2018-2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

/** @file */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT

#if SSS_HAVE_HOSTCRYPTO_USER
#include <fsl_sss_user_apis.h>
#endif

#if defined(FLOW_VERBOSE)
#define NX_LOG_ENABLE_SCP_DEBUG 1
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY

#include <fsl_sss_se05x_scp03.h>
#include <nxLog_scp.h>
#include <se05x_tlv.h>
#include <string.h>

#include "nxEnsure.h"
#include "nxScp03_Apis.h"
#include "smCom.h"
#include "fsl_sss_lpc55s_apis.h"

/* ************************************************************************** */
/* Functions : Private function declaration                                   */
/* ************************************************************************** */

//#define INITIAL_HOST_CHALLANGE {0xAF,0x28,0xE1,0x16,0xD1,0x58,0x1E,0x89}

/**
* To Initiate secure channel
*/
static sss_status_t nxScp03_GP_InitializeUpdate(pSe05xSession_t se05xSession,
    uint8_t *hostChallenge,
    uint16_t hostChallengeLen,
    uint8_t *keyDivData,
    uint16_t *pKeyDivDataLen,
    uint8_t *keyInfo,
    uint16_t *pKeyInfoLen,
    uint8_t *cardChallenge,
    uint16_t *pCardChallengeLen,
    uint8_t *cardCryptoGram,
    uint16_t *pCardCryptoGramLen,
    uint8_t *seqCounter,
    uint16_t *pSeqCounterLen,
    uint8_t keyVerNo);

static sss_status_t nxScp03_HostLocal_CalculateSessionKeys(
    NXSCP03_AuthCtx_t *pAuthScp03, uint8_t *hostChallenge, uint8_t *cardChallenge);

/**
* To authenticate the initiated secure channel
*/
static sss_status_t nxScp03_GP_ExternalAuthenticate(
    pSe05xSession_t se05xSession, sss_object_t *keyObj, uint8_t *updateMCV, uint8_t *hostCryptogram);

sss_status_t nxScp03_AuthenticateChannel(pSe05xSession_t se05xSession, NXSCP03_AuthCtx_t *pAuthScp03)
{
#ifdef INITIAL_HOST_CHALLANGE
    uint8_t hostChallenge[] = INITIAL_HOST_CHALLANGE;
#else
    uint8_t hostChallenge[SCP_GP_HOST_CHALLENGE_LEN];
    sss_rng_context_t rngctx;
#endif
    uint8_t keyDivData[SCP_GP_IU_KEY_DIV_DATA_LEN];
    uint16_t keyDivDataLen = sizeof(keyDivData);
    uint8_t keyInfo[SCP_GP_IU_KEY_INFO_LEN];
    uint16_t keyInfoLen = sizeof(keyInfo);
    uint8_t cardChallenge[SCP_GP_CARD_CHALLENGE_LEN];
    uint16_t cardChallengeLen = sizeof(cardChallenge);
    uint8_t cardCryptoGram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    uint16_t cardCryptoGramLen = sizeof(cardCryptoGram);
    uint8_t seqCounter[SCP_GP_IU_SEQ_COUNTER_LEN];
    uint16_t seqCounterLen = sizeof(seqCounter);
    uint8_t hostCryptogram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];

    NXSCP03_StaticCtx_t *pStatic_ctx = pAuthScp03->pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = pAuthScp03->pDyn_ctx;

    /* clang-format off */
    const uint8_t commandCounter[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    /* clang-format on */
    sss_status_t status = kStatus_SSS_Fail;

    if ((pStatic_ctx->Enc.keyStore == NULL) || (pStatic_ctx->Mac.keyStore == NULL) ||
        (pStatic_ctx->Dek.keyStore == NULL) || (pDyn_ctx->Enc.keyStore == NULL) || (pDyn_ctx->Mac.keyStore == NULL) ||
        (pDyn_ctx->Rmac.keyStore == NULL)) {
        LOG_E("nxScp03_GP_InitializeUpdate fails Invalid objects sent %04X", status);
        return status;
    }
    LOG_D("FN: %s", __FUNCTION__);
    /* Get a random host challenge */
#ifndef INITIAL_HOST_CHALLANGE
    status = sss_host_rng_context_init(&rngctx, pStatic_ctx->Enc.keyStore->session);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_rng_get_random(&rngctx, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    LOG_MAU8_D(" Output: hostChallenge", hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);

    sss_host_rng_context_free(&rngctx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif

    status = nxScp03_GP_InitializeUpdate(se05xSession,
        hostChallenge,
        sizeof(hostChallenge),
        keyDivData,
        &keyDivDataLen,
        keyInfo,
        &keyInfoLen,
        cardChallenge,
        &cardChallengeLen,
        cardCryptoGram,
        &cardCryptoGramLen,
        seqCounter,
        &seqCounterLen,
        pStatic_ctx->keyVerNo);

    if (status != kStatus_SSS_Success) {
        LOG_E("nxScp03_GP_InitializeUpdate fails with Status %04X", status);
        return status;
    }

    status = nxScp03_HostLocal_CalculateSessionKeys(pAuthScp03, hostChallenge, cardChallenge);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nxScp03_HostLocal_VerifyCardCryptogram(&pDyn_ctx->Mac, hostChallenge, cardChallenge, cardCryptoGram);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D("cardCryptoGram", cardCryptoGram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    LOG_D("CardCryptogram verified successfully...Calculate HostCryptogram");
    status = nxScp03_HostLocal_CalculateHostCryptogram(&pDyn_ctx->Mac, hostChallenge, cardChallenge, hostCryptogram);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_AU8_D(hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    status = nxScp03_GP_ExternalAuthenticate(se05xSession, &pDyn_ctx->Mac, pDyn_ctx->MCV, hostCryptogram);
    if (status != kStatus_SSS_Success) {
        LOG_E("GP_ExternalAuthenticate fails with Status %04X", status);
        return status;
    }
    else {
        // At this stage we have authenticated successfully.
        status                  = kStatus_SSS_Success;
        pDyn_ctx->SecurityLevel = (C_MAC | C_ENC | R_MAC | R_ENC);
        memcpy(pDyn_ctx->cCounter, commandCounter, AES_KEY_LEN_nBYTE);
        LOG_D("Authentication Successful!!!");
    }

exit:
    return status;
}

static sss_status_t nxScp03_GP_ExternalAuthenticate(
    pSe05xSession_t se05xSession, sss_object_t *keyObj, uint8_t *updateMCV, uint8_t *hostCryptogram)
{
    smStatus_t st = 0;
    uint8_t txBuf[64];
    uint8_t macToAdd[AES_KEY_LEN_nBYTE];

    sss_mac_t macCtx;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode           = kMode_SSS_Mac;
    size_t signatureLen       = sizeof(macToAdd);
    sss_status_t status       = kStatus_SSS_Fail;

    tlvHeader_t hdr = {
        {CLA_GP_7816 | CLA_GP_SECURITY_BIT, INS_GP_EXTERNAL_AUTHENTICATE, SECLVL_CDEC_RENC_CMAC_RMAC, 0x00}};

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: hostCryptogram", hostCryptogram, SCP_COMMAND_MAC_SIZE);

    txBuf[0] = CLA_GP_7816 | CLA_GP_SECURITY_BIT; //Set CLA Byte

    txBuf[1] = INS_GP_EXTERNAL_AUTHENTICATE; //Set INS Byte
    txBuf[2] = SECLVL_CDEC_RENC_CMAC_RMAC;   //Set Security Level

    txBuf[3] = 0x00;
    txBuf[4] = 0x10; // The Lc value is set as-if the MAC has already been appended (SCP03 spec p16. Fig.6-1)
    memcpy(&txBuf[5], hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    LOG_D("Calculate the MAC on data");
    // Calculate the MAC value
    status = sss_host_mac_context_init(&macCtx, keyObj->keyStore->session, keyObj, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_mac_init(&macCtx);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /*
    * For the EXTERNAL AUTHENTICATE command MAC verification, the "MAC chaining value" is set to 16
    * bytes '00'. (SCP03 spec p16)
    */
    memset(updateMCV, 0, SCP_MCV_LEN);

    status = sss_host_mac_update(&macCtx, updateMCV, AES_KEY_LEN_nBYTE);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_mac_update(&macCtx, txBuf, 13);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_mac_finish(&macCtx, macToAdd, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(" Output: Calculated MAC", macToAdd, SCP_COMMAND_MAC_SIZE);
    sss_host_mac_context_free(&macCtx);

    LOG_D("Add calculated MAC Value to cmd Data");
    memcpy(updateMCV, macToAdd, AES_KEY_LEN_nBYTE);
    memcpy(&txBuf[5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN], macToAdd, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    LOG_D("Sending GP External Authenticate Command !!!");
    st = DoAPDUTx_s_Case3(se05xSession, &hdr, &txBuf[5], 16);
    if (st != SM_OK) {
        LOG_E("GP_ExternalAuthenticate returns %lX", st);
        status = kStatus_SSS_Fail;
    }
    else {
        status = kStatus_SSS_Success;
    }

exit:
    return status;
}

sss_status_t nxScp03_HostLocal_CalculateHostCryptogram(
    sss_object_t *keyObj, uint8_t *hostChallenge, uint8_t *cardChallenge, uint8_t *hostCryptogram)
{
    uint8_t ddA[128];
    uint16_t ddALen = sizeof(ddA);
    uint8_t context[128];
    uint16_t contextLen = 0;
    uint8_t hostCryptogramFullLength[AES_KEY_LEN_nBYTE];
    uint32_t signatureLen = sizeof(hostCryptogramFullLength);
    sss_status_t status   = kStatus_SSS_Fail;

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:hostChallenge", hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    LOG_MAU8_D(" Input:cardChallenge", cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_HOST_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);

    status = nxScp03_Generate_SessionKey(keyObj, ddA, ddALen, hostCryptogramFullLength, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(" Output:hostCryptogram", hostCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Chop of the tail of the hostCryptogramFullLength
    memcpy(hostCryptogram, hostCryptogramFullLength, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
exit:
    return status;
}

sss_status_t nxScp03_HostLocal_VerifyCardCryptogram(
    sss_object_t *keyObj, uint8_t *hostChallenge, uint8_t *cardChallenge, uint8_t *cardCryptogram)
{
    uint8_t ddA[128];
    uint16_t ddALen = sizeof(ddA);
    uint8_t context[128];
    uint16_t contextLen = 0;
    uint8_t cardCryptogramFullLength[AES_KEY_LEN_nBYTE];
    uint32_t signatureLen = sizeof(cardCryptogramFullLength);
    sss_status_t status   = kStatus_SSS_Fail;

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:hostChallenge", hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    LOG_MAU8_D(" Input:cardChallenge", cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_CARD_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);

    status = nxScp03_Generate_SessionKey(keyObj, ddA, ddALen, cardCryptogramFullLength, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(" Output:cardCryptogram", cardCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Verify whether the 8 left most byte of cardCryptogramFullLength match cardCryptogram
    if (memcmp(cardCryptogramFullLength, cardCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != 0)
        status = kStatus_SSS_Fail;
exit:
    return status;
}

static sss_status_t nxScp03_HostLocal_CalculateSessionKeys(
    NXSCP03_AuthCtx_t *pAuthScp03, uint8_t *hostChallenge, uint8_t *cardChallenge)
{
    uint8_t ddA[128];
    uint16_t ddALen = sizeof(ddA);
    uint8_t context[128];
    uint16_t contextLen = 0;
    uint8_t sessionEncKey[AES_KEY_LEN_nBYTE];
    uint8_t sessionMacKey[AES_KEY_LEN_nBYTE];
    uint8_t sessionRmacKey[AES_KEY_LEN_nBYTE];
    uint32_t signatureLen            = AES_KEY_LEN_nBYTE;
    sss_status_t status              = kStatus_SSS_Fail;
    NXSCP03_StaticCtx_t *pStatic_ctx = pAuthScp03->pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = pAuthScp03->pDyn_ctx;

    // Calculate the Derviation data
    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:hostChallenge", hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    LOG_MAU8_D(" Input:cardChallenge", cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);

    /* Generation and Creation of Session ENC SSS Key Object */

    // Set the Derviation data
    LOG_D("Set the Derviation data to generate Session ENC key");
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    // Calculate the Session-ENC key
    status = nxScp03_Generate_SessionKey(&pStatic_ctx->Enc, ddA, ddALen, sessionEncKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D(" Output:sessionEncKey", sessionEncKey, AES_KEY_LEN_nBYTE);

    // Set the Session-ENC key
    status = sss_host_key_store_set_key(pDyn_ctx->Enc.keyStore, &pDyn_ctx->Enc, sessionEncKey, 16, (16) * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Generation and Creation of Session MAC SSS Key Object */

    // Set the Derviation data
    LOG_D("Set the Derviation data to generate Session MAC key");
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    // Calculate the Session-MAC key
    status = nxScp03_Generate_SessionKey(&pStatic_ctx->Mac, ddA, ddALen, sessionMacKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D(" Output:sessionMacKey", sessionMacKey, AES_KEY_LEN_nBYTE);

    // Set the Session-MAC key
    status = sss_host_key_store_set_key(pDyn_ctx->Mac.keyStore, &pDyn_ctx->Mac, sessionMacKey, 16, (16) * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    /* Generation and Creation of Session RMAC SSS Key Object */
    // Set the Derviation data
    LOG_D("Set the Derviation data to generate Session RMAC key");
    nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    // Calculate the Session-RMAC key
    status = nxScp03_Generate_SessionKey(&pStatic_ctx->Mac, ddA, ddALen, sessionRmacKey, &signatureLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D(" Output:sessionRmacKey", sessionRmacKey, AES_KEY_LEN_nBYTE);

    // Set the Session-RMAC key
    status =
        sss_host_key_store_set_key(pDyn_ctx->Rmac.keyStore, &pDyn_ctx->Rmac, sessionRmacKey, 16, (16) * 8, NULL, 0);
exit:
    return status;
}

sss_status_t nxScp03_Generate_SessionKey(
    sss_object_t *keyObj, uint8_t *inData, uint32_t inDataLen, uint8_t *outSignature, uint32_t *outSignatureLen)
{
    sss_mac_t macCtx;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode           = kMode_SSS_Mac;
    sss_status_t status       = kStatus_SSS_Fail;
    size_t sigLen             = *outSignatureLen;
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input: inData", inData, inDataLen);
    // Init MAC Context
    status = sss_host_mac_context_init(&macCtx, keyObj->keyStore->session, keyObj, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Calculate Session key with MAC one go
    status           = sss_host_mac_one_go(&macCtx, inData, inDataLen, outSignature, &sigLen);
    *outSignatureLen = (uint32_t)sigLen;
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(" Output:outSignature", outSignature, *outSignatureLen);

    // Free MAC context
    sss_host_mac_context_free(&macCtx);
exit:
    return status;
}

static sss_status_t nxScp03_GP_InitializeUpdate(pSe05xSession_t se05xSession,
    uint8_t *hostChallenge,
    uint16_t hostChallengeLen,
    uint8_t *keyDivData,
    uint16_t *pKeyDivDataLen,
    uint8_t *keyInfo,
    uint16_t *pKeyInfoLen,
    uint8_t *cardChallenge,
    uint16_t *pCardChallengeLen,
    uint8_t *cardCryptoGram,
    uint16_t *pCardCryptoGramLen,
    uint8_t *seqCounter,
    uint16_t *pSeqCounterLen,
    uint8_t keyVerNo)
{
    smStatus_t st = 0;
    uint8_t response[64];
    size_t responseLen          = 64;
    uint16_t parsePos           = 0;
    uint16_t sw                 = 0;
    uint32_t iuResponseLenSmall = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                  SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_SW_LEN;
    uint32_t iuResponseLenBig = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_IU_SEQ_COUNTER_LEN + SCP_GP_SW_LEN;
    sss_status_t status = kStatus_SSS_Fail;
    /* Default Key version no for applet scp is 0x00*/
    uint8_t keyVersion = 0x00;
    if (se05xSession->authType == kSSS_AuthType_SCP03) {
        /* Key version no. for Platform SCP03 passed by user*/
        keyVersion = keyVerNo;
        /*Initialise update and external authenticate should go with auth type None
        For Platform SCP03 as this is the authentication without session with JCOP */
        se05xSession->authType = kSSS_AuthType_None;
    }

    tlvHeader_t hdr = {{CLA_GP_7816, INS_GP_INITIALIZE_UPDATE, keyVersion, 0x00}};

    uint8_t cmdBuf[60];
    ENSURE_OR_GO_CLEANUP(hostChallengeLen == SCP_GP_HOST_CHALLENGE_LEN);
    ENSURE_OR_GO_CLEANUP(*pKeyDivDataLen == SCP_GP_IU_KEY_DIV_DATA_LEN);
    ENSURE_OR_GO_CLEANUP(*pKeyInfoLen == SCP_GP_IU_KEY_INFO_LEN);
    ENSURE_OR_GO_CLEANUP(*pCardChallengeLen == SCP_GP_CARD_CHALLENGE_LEN);
    ENSURE_OR_GO_CLEANUP(*pCardCryptoGramLen == SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    LOG_D("FN: %s", __FUNCTION__);
    LOG_D("Input:keyVersion %02x", keyVersion);
    LOG_MAU8_D(" Input: hostChallenge", hostChallenge, hostChallengeLen);
    LOG_D("Sending GP Initialize Update Command !!!");
    memcpy(cmdBuf, hostChallenge, hostChallengeLen);
    st = DoAPDUTxRx_s_Case4(se05xSession, &hdr, cmdBuf, hostChallengeLen, response, &responseLen);
    if (st != SM_OK) {
        LOG_E("GP_InitializeUpdate Failure on communication Link %04X", st);
        return status;
    }

    // Parse Response
    // The expected result length depends on random (HOST-Channel) or pseudo-random (ADMIN-Channel) challenge type.
    // The pseudo-random challenge case also includes a 3 byte sequence counter
    if ((responseLen != iuResponseLenSmall) && (responseLen != iuResponseLenBig)) {
        // Note: A response of length 2 (a proper SW) is also collapsed into return code SCP_FAIL
        LOG_E("GP_InitializeUpdate Unexpected amount of data returned: %04X", responseLen);
        return status;
    }

    memcpy(keyDivData, response, SCP_GP_IU_KEY_DIV_DATA_LEN);
    parsePos = SCP_GP_IU_KEY_DIV_DATA_LEN;
    memcpy(keyInfo, &(response[parsePos]), SCP_GP_IU_KEY_INFO_LEN);
    parsePos += SCP_GP_IU_KEY_INFO_LEN;
    memcpy(cardChallenge, &(response[parsePos]), SCP_GP_CARD_CHALLENGE_LEN);
    parsePos += SCP_GP_CARD_CHALLENGE_LEN;
    memcpy(cardCryptoGram, &(response[parsePos]), SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    parsePos += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    // Construct Return Value
    sw = (response[responseLen - 2] << 8) + response[responseLen - 1];
    if (sw == SM_OK) {
        LOG_MAU8_D(" Output: keyDivData", keyDivData, *pKeyDivDataLen);
        LOG_MAU8_D(" Output: keyInfo", keyInfo, *pKeyInfoLen);
        LOG_MAU8_D(" Output: cardChallenge", cardChallenge, *pCardChallengeLen);
        LOG_MAU8_D(" Output: cardCryptoGram", cardCryptoGram, *pCardCryptoGramLen);
        status = kStatus_SSS_Success;
    }
cleanup:
    return status;
}

void nxScp03_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    uint8_t *context,
    uint16_t contextLen)
{
    LOG_D("FN: %s", __FUNCTION__);
    LOG_D("Input:ddConstant %02x", ddConstant);
    LOG_D("Input:ddL %02x", ddL);
    LOG_D("Input:iCounter %02x", iCounter);
    LOG_MAU8_D(" Input: keyInfo", context, contextLen);
    // SCPO3 spec p9&10
    memset(ddA, 0, DD_LABEL_LEN - 1);
    ddA[DD_LABEL_LEN - 1] = ddConstant;
    ddA[DD_LABEL_LEN]     = 0x00; // Separation Indicator
    ddA[DD_LABEL_LEN + 1] = (uint8_t)(ddL >> 8);
    ddA[DD_LABEL_LEN + 2] = (uint8_t)ddL;
    ddA[DD_LABEL_LEN + 3] = iCounter;
    memcpy(&ddA[DD_LABEL_LEN + 4], context, contextLen);
    *pDdALen = DD_LABEL_LEN + 4 + contextLen;

    LOG_MAU8_D("Output: KeyDivData", ddA, *pDdALen);
}

#endif // SSS_HAVE_HOSTCRYPTO_ANY

#endif // SSS_HAVE_APPLET_SE05X_IOT
