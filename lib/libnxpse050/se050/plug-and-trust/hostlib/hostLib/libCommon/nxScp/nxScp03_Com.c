/*
* Copyright 2018,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#if defined(FLOW_VERBOSE)
#define NX_LOG_ENABLE_SCP_DEBUG 1
#endif

#include <string.h>
#include <assert.h>
#include "smCom.h"
#include <nxLog_scp.h>
#include "nxScp03_Apis.h"
#include "nxEnsure.h"
#include "se05x_const.h"

#if defined(SE05X_MAX_BUF_SIZE_CMD) && (SE05X_MAX_BUF_SIZE_CMD != 892)
#   error "Expect hard coded for SE05X_MAX_BUF_SIZE_CMD = 892"
#endif

#define NX_SCP03_MAX_BUFFER_SIZE 0x380 /* 0x380 = 896 */

/* ************************************************************************** */
/* Functions : Private function declaration                                   */
/* ************************************************************************** */
/**
* To Apply Encryption on Plain Data
*/

static void nxSCP03_PadCommandAPDU(uint8_t *cmdBuf, size_t *pCmdBufLen);
/**
* To Maintain chaining of Sent commands
*/
static sss_status_t nxSCP03_Calculate_CommandICV(NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pIcv);


/**
* To Maintain chaining of Receive commands
*/
static sss_status_t nxpSCP03_Get_ResponseICV(NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pIcv, bool hasCmd);
/**
* To check plain data
*/
static uint16_t nxpSCP03_RestoreSw_RAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen, uint8_t *sw);

/**
* Decrement counter block for ICV calculation
*/
static void nxpSCP03_Dec_CommandCounter(uint8_t *pCtrblock);

sss_status_t nxSCP03_Encrypt_CommandAPDU(NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *cmdBuf, size_t *pCmdBufLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    size_t dataLen = 0;

    ENSURE_OR_GO_CLEANUP(pCmdBufLen != NULL);
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:cmdBuf", cmdBuf, *pCmdBufLen);

    if (*pCmdBufLen != 0) {
        sss_symmetric_t symm;
        uint8_t iv[16] = {0};
        uint8_t *pIv = (uint8_t *)iv;
        uint8_t apduPayloadToEncrypt[NX_SCP03_MAX_BUFFER_SIZE] = {0};

        /* Prior to encrypting the data, the data shall be padded as defined in section 4.1.4.
        This padding becomes part of the data field.*/
        nxSCP03_PadCommandAPDU(cmdBuf, pCmdBufLen);
        sss_status = nxSCP03_Calculate_CommandICV(pdySCP03SessCtx, pIv);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
        memcpy(apduPayloadToEncrypt, cmdBuf, *pCmdBufLen);

        sss_status = sss_host_symmetric_context_init(&symm,
            pdySCP03SessCtx->Enc.keyStore->session,
            &pdySCP03SessCtx->Enc,
            kAlgorithm_SSS_AES_CBC,
            kMode_SSS_Encrypt);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
        dataLen = *pCmdBufLen;
        LOG_D("Encrypt CommandAPDU");
        sss_status = sss_host_cipher_one_go(&symm, pIv, SCP_KEY_SIZE, apduPayloadToEncrypt, cmdBuf, dataLen);
        ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
        LOG_AU8_D(cmdBuf, dataLen);
        LOG_MAU8_D("Output: EncryptedcmdBuf", cmdBuf, dataLen);
        sss_host_symmetric_context_free(&symm);
    }
    else {
        /* Nothing to encrypt */
        sss_status = kStatus_SSS_Success;
    }


cleanup:
    return sss_status;
}

uint16_t nxpSCP03_Decrypt_ResponseAPDU(
    NXSCP03_DynCtx_t *pdySCP03SessCtx, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen, uint8_t hasle)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint16_t status = SCP_FAIL;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode = kMode_SSS_Mac;
    sss_mac_t macCtx;
    uint8_t sw[SCP_GP_SW_LEN];
    uint8_t respMac[SCP_CMAC_SIZE];
    size_t signatureLen = sizeof(respMac);
    size_t compareoffset = 0;
    size_t macSize = SCP_CMAC_SIZE;
    uint8_t iv[SCP_IV_SIZE];
    uint8_t *pIv = (uint8_t *)iv;
    uint8_t response[NX_SCP03_MAX_BUFFER_SIZE];
    uint8_t plaintextResponse[NX_SCP03_MAX_BUFFER_SIZE];
    sss_algorithm_t algorithm_aes = kAlgorithm_SSS_AES_CBC;
    sss_mode_t mode_aes = kMode_SSS_Decrypt;
    sss_symmetric_t symm;
    size_t actualRespLen = 0;

    ENSURE_OR_GO_EXIT(pRspBufLen != NULL);
    ENSURE_OR_GO_EXIT(pdySCP03SessCtx != NULL);
    ENSURE_OR_GO_EXIT(rspBuf != NULL);

    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D(" Input:rspBuf", rspBuf, *pRspBufLen);


    if (*pRspBufLen >= (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
        memcpy(sw, &(rspBuf[*pRspBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);

        sss_status = sss_host_mac_context_init(
            &macCtx, pdySCP03SessCtx->Rmac.keyStore->session, &pdySCP03SessCtx->Rmac, algorithm, mode);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_init(&macCtx);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_update(&macCtx, pdySCP03SessCtx->MCV, macSize);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_update(&macCtx, rspBuf, *pRspBufLen - SCP_COMMAND_MAC_SIZE - SCP_GP_SW_LEN);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_update(&macCtx, sw, SCP_GP_SW_LEN);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_mac_finish(&macCtx, respMac, &signatureLen);

        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
        LOG_MAU8_D(" Calculated RMAC :", respMac, signatureLen);
        sss_host_mac_context_free(&macCtx);
        LOG_D("Verify MAC");
        // Do a comparison of the received and the calculated mac
        compareoffset = *pRspBufLen - SCP_COMMAND_MAC_SIZE - SCP_GP_SW_LEN;
        if (memcmp(respMac, &rspBuf[compareoffset], SCP_COMMAND_MAC_SIZE) != 0) {
            LOG_E(" RESPONSE MAC DID NOT VERIFY %04X", status);
            return status;
        }
    }

    LOG_D("RMAC verified successfully...Decrypt Response Data");
    // Decrypt Response Data Field in case Reponse Mac verified OK
    if (*pRspBufLen > (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
        // There is data payload in response
        size_t dataLen = 0;
        memcpy(response, rspBuf, (*pRspBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN));
        //LOG_MAU8_D(" EncResponse", response, (*pRspBufLen) - 10);

        memcpy(sw, &(rspBuf[*pRspBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);
        LOG_MAU8_D("Status Word: ", sw, 2);

        // Calculate ICV to decrypt the response
        sss_status = nxpSCP03_Get_ResponseICV(pdySCP03SessCtx, pIv, cmdBufLen == 0 ? FALSE : TRUE);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        sss_status = sss_host_symmetric_context_init(
            &symm, pdySCP03SessCtx->Enc.keyStore->session, &pdySCP03SessCtx->Enc, algorithm_aes, mode_aes);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        dataLen = (*pRspBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN);
        LOG_D("Decrypt the response");
        // Decrypt the response
        sss_status = sss_host_cipher_one_go(&symm, pIv, SCP_KEY_SIZE, response, plaintextResponse, dataLen);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

        LOG_MAU8_D("PlainText", plaintextResponse, (*pRspBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN));
        sss_host_symmetric_context_free(&symm);
        actualRespLen = (*pRspBufLen) - (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN);
        /*Remove the padding from the plaintextResponse*/
        sss_status = kStatus_SSS_Fail;
        status = nxpSCP03_RestoreSw_RAPDU(rspBuf, pRspBufLen, plaintextResponse, actualRespLen, sw);
        if (status == SCP_OK) {
            sss_status = kStatus_SSS_Success;
        }
    }
    else if ((*pRspBufLen) == (SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN)) {
        // There's no data payload in response
        memcpy(rspBuf, sw, SCP_GP_SW_LEN);
        *pRspBufLen = SCP_GP_SW_LEN;
        sss_status = kStatus_SSS_Success;
    }

    if (sss_status == kStatus_SSS_Success) {
        status = SCP_OK;
    }

    if (((pdySCP03SessCtx->authType == kSSS_AuthType_AESKey) || (pdySCP03SessCtx->authType == kSSS_AuthType_ECKey)) ||
        ((pdySCP03SessCtx->authType == kSSS_AuthType_SCP03) && cmdBufLen > 0)) {
        status = SCP_OK;
        nxpSCP03_Inc_CommandCounter(pdySCP03SessCtx);
    }

exit:
    return status;
}

static uint16_t nxpSCP03_RestoreSw_RAPDU(
    uint8_t *rspBuf, size_t *pRspBufLen, uint8_t *plaintextResponse, size_t plaintextRespLen, uint8_t *sw)
{
    uint16_t status = SCP_DECODE_FAIL;
    size_t i;
    int removePaddingOk = 0;

    i = plaintextRespLen;

    ENSURE_OR_GO_EXIT(pRspBufLen != NULL);
    ENSURE_OR_GO_EXIT(plaintextResponse != NULL);
    ENSURE_OR_GO_EXIT(rspBuf != NULL);
    ENSURE_OR_GO_EXIT(sw != NULL);

    LOG_D("FN: %s", __FUNCTION__);

    while ((i > 1) && (i > (plaintextRespLen - SCP_KEY_SIZE))) {
        if (plaintextResponse[i - 1] == 0x00) {
            i--;
        }
        else if (plaintextResponse[i - 1] == SCP_DATA_PAD_BYTE) {
            // We have found padding delimitor
            memcpy(&plaintextResponse[i - 1], sw, SCP_GP_SW_LEN);
            memcpy(rspBuf, plaintextResponse, i + 1);
            *pRspBufLen = (i + 1);
            removePaddingOk = 1;
            LOG_MAU8_D("PlainText+SW", rspBuf, *pRspBufLen);
            break;
        }
        else {
            // We've found a non-padding character while removing padding
            // Most likely the cipher text was not properly decoded.
            LOG_E("RAPDU Decoding failed No Padding found %04X", status);
            break;
        }
    }

    if (removePaddingOk == 0) {
        return status;
    }
    status = SCP_OK;
exit:
    return status;
}

static sss_status_t nxpSCP03_Get_ResponseICV(NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pIcv, bool hasCmd)
{
    uint8_t ivZero[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    sss_status_t status = kStatus_SSS_Fail;
    sss_symmetric_t symm;
    size_t dataLen = 0;
    uint8_t paddedCounterBlock[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ENSURE_OR_GO_EXIT(pdySCP03SessCtx != NULL);
    LOG_D("FN: %s", __FUNCTION__);

    memcpy(paddedCounterBlock, pdySCP03SessCtx->cCounter, SCP_KEY_SIZE);
    if ((pdySCP03SessCtx->authType == kSSS_AuthType_SCP03) && (!hasCmd)) {
        nxpSCP03_Dec_CommandCounter(paddedCounterBlock);
    }
    paddedCounterBlock[0] = SCP_DATA_PAD_BYTE; // MSB padded with 0x80 Section 6.2.7 of SCP03 spec

    LOG_MAU8_D(" Input:Data", paddedCounterBlock, SCP_KEY_SIZE);

    status = sss_host_symmetric_context_init(&symm,
        pdySCP03SessCtx->Enc.keyStore->session,
        &pdySCP03SessCtx->Enc,
        kAlgorithm_SSS_AES_CBC,
        kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    dataLen = SCP_KEY_SIZE;
    status = sss_host_cipher_one_go(&symm, ivZero, SCP_KEY_SIZE, paddedCounterBlock, pIcv, dataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D(" Output:RespICV", pIcv, dataLen);
    sss_host_symmetric_context_free(&symm);
exit:
    return status;
}

void nxpSCP03_Inc_CommandCounter(NXSCP03_DynCtx_t *pdySCP03SessCtx)
{
    int i = 15;
    ENSURE_OR_GO_EXIT(pdySCP03SessCtx != NULL);
    while (i > 0) {
        if (pdySCP03SessCtx->cCounter[i] < 255) {
            pdySCP03SessCtx->cCounter[i] += 1;
            break;
        }
        else {
            pdySCP03SessCtx->cCounter[i] = 0;
            i--;
        }
    }

    LOG_MAU8_D("Inc_CommandCounter value ", pdySCP03SessCtx->cCounter, SCP_KEY_SIZE);
exit:
    return;
}

static void nxpSCP03_Dec_CommandCounter(uint8_t *pCtrblock)
{
    int i = 15;
    ENSURE_OR_GO_EXIT(pCtrblock != NULL);
    while (i > 0) {
        if (pCtrblock[i] == 0) {
            pCtrblock[i] = 0xFF;
            i--;
        }
        else {
            pCtrblock[i]--;
            break;
        }
    }
exit:
    return;
}

sss_status_t nxpSCP03_CalculateMac_CommandAPDU(
    NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pCmdBuf, size_t cmdBufLen, uint8_t *mac, size_t *macLen)
{
    sss_status_t sss_status = kStatus_SSS_Fail;
    sss_mac_t macCtx;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode = kMode_SSS_Mac;

    ENSURE_OR_GO_EXIT(pdySCP03SessCtx != NULL);
    ENSURE_OR_GO_EXIT(mac != NULL);
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D("Input: cmdBuf", pCmdBuf, cmdBufLen);

    sss_status =
        sss_host_mac_context_init(&macCtx, pdySCP03SessCtx->Mac.keyStore->session, &pdySCP03SessCtx->Mac, algorithm, mode);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_mac_init(&macCtx);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_mac_update(&macCtx, pdySCP03SessCtx->MCV, SCP_KEY_SIZE);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_mac_update(&macCtx, pCmdBuf, cmdBufLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    sss_status = sss_host_mac_finish(&macCtx, mac, macLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    LOG_MAU8_D("Output: mac", mac, SCP_COMMAND_MAC_SIZE);
    sss_host_mac_context_free(&macCtx);
    // Store updated mcv!
    memcpy(pdySCP03SessCtx->MCV, mac, SCP_MCV_LEN);

exit:
    return sss_status;
}

static sss_status_t nxSCP03_Calculate_CommandICV(NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pIcv)
{
    uint8_t ivZero[SCP_KEY_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    sss_status_t status = kStatus_SSS_Fail;
    sss_symmetric_t symm;
    size_t dataLen = 0;

    ENSURE_OR_GO_EXIT(pdySCP03SessCtx != NULL);
    LOG_D("FN: %s", __FUNCTION__);


    status = sss_host_symmetric_context_init(&symm,
        pdySCP03SessCtx->Enc.keyStore->session,
        &pdySCP03SessCtx->Enc,
        kAlgorithm_SSS_AES_CBC,
        kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    dataLen = SCP_KEY_SIZE;
    status = sss_host_cipher_one_go(&symm, ivZero, SCP_KEY_SIZE, pdySCP03SessCtx->cCounter, pIcv, dataLen);
    sss_host_symmetric_context_free(&symm);
    LOG_MAU8_D(" Output:", pIcv, SCP_COMMAND_MAC_SIZE);
exit:
    return status;
}

static void nxSCP03_PadCommandAPDU(uint8_t *cmdBuf, size_t *pCmdBufLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_GO_EXIT(pCmdBufLen != NULL);
    ENSURE_OR_GO_EXIT(cmdBuf != NULL);
    LOG_D("FN: %s", __FUNCTION__);
    LOG_MAU8_D("Input: cmdBuf", cmdBuf, *pCmdBufLen);
    // pad the payload and adjust the length of the APDU
    cmdBuf[(*pCmdBufLen)] = SCP_DATA_PAD_BYTE;
    *pCmdBufLen += 1;
    zeroBytesToPad = (SCP_KEY_SIZE - ((*pCmdBufLen) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;

    while (zeroBytesToPad > 0) {
        cmdBuf[(*pCmdBufLen)] = 0x00;
        *pCmdBufLen += 1;
        zeroBytesToPad--;
    }
    LOG_MAU8_D("Ouput: cmdBuf", cmdBuf, *pCmdBufLen);

exit:
    return;
}
