/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "se05x_tlv.h"
#include "se05x_const.h"
#include <string.h> // memcpy
#include <nxLog_sss.h>
#include <nxScp03_Apis.h>
#include "nxEnsure.h"
#include "smCom.h"
#include "sm_apdu.h"

#ifdef FLOW_VERBOSE
#define VERBOSE_APDU_LOGS 1
#else
#define VERBOSE_APDU_LOGS 0
#endif

#if SSS_HAVE_SE05X
#define SE05X_TLV_BUF_SIZE_CMD SE05X_MAX_BUF_SIZE_CMD
#define SE05X_TLV_BUF_SIZE_RSP SE05X_MAX_BUF_SIZE_RSP
#else
#define SE05X_TLV_BUF_SIZE_CMD 900
#define SE05X_TLV_BUF_SIZE_RSP 900
#endif

int tlvSet_U8(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint8_t value)
{
    uint8_t *pBuf            = *buf;
    const size_t size_of_tlv = 1 + 1 + 1;
    if (((*bufLen) + size_of_tlv) > SE05X_TLV_BUF_SIZE_CMD)
        return 1;
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 1;
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    if (value == 0)
        return 0;
    else
        return tlvSet_U16(buf, bufLen, tag, value);
}

int tlvSet_U16(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    const size_t size_of_tlv = 1 + 1 + 2;
    uint8_t *pBuf            = *buf;
    if (((*bufLen) + size_of_tlv) > SE05X_TLV_BUF_SIZE_CMD)
        return 1;
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 2;
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U32(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t value)
{
    const size_t size_of_tlv = 1 + 1 + 4;
    uint8_t *pBuf            = *buf;
    if (((*bufLen) + size_of_tlv) > SE05X_TLV_BUF_SIZE_CMD)
        return 1;
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 4;
    *pBuf++ = (uint8_t)((value >> 3 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U64_size(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint64_t value, uint16_t size)
{
    int8_t pos               = 0;
    pos                      = (uint8_t)size;
    const size_t size_of_tlv = 1 + 1 + size;
    uint8_t *pBuf            = *buf;
    if (((*bufLen) + size_of_tlv) > SE05X_TLV_BUF_SIZE_CMD)
        return 1;
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = pos;
    pos--;
    for (; pos >= 0; pos--) {
        *pBuf++ = (uint8_t)((value >> pos * 8) & 0xFF);
    }
    *buf = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_Se05xPolicy(const char *description, uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, Se05xPolicy_t *policy)
{
    int tlvRet = 0;
    if ((policy != NULL) && (policy->value != NULL)) {
        tlvRet = tlvSet_u8buf(buf, bufLen, tag, policy->value, policy->value_len);
#if VERBOSE_APDU_LOGS
        nLog("APDU", NX_LEVEL_DEBUG, "kSE05x_TAG_POLICY");
        nLog_au8("APDU", NX_LEVEL_DEBUG, description, policy->value, policy->value_len);
#endif
        return tlvRet;
    }
    else {
#if VERBOSE_APDU_LOGS
        nLog("APDU", NX_LEVEL_INFO, "Policy is NULL");
#endif
    }

    return tlvRet;
}

int tlvSet_ECCurve(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, SE05x_ECCurve_t value)
{
    int retVal = 0;
    if (value != kSE05x_ECCurve_NA)
        retVal = tlvSet_U8(buf, bufLen, tag, (uint8_t)value);
    return retVal;
}

int tlvSet_u8bufOptional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    if (cmdLen == 0)
        return 0;
    else
        return tlvSet_u8buf(buf, bufLen, tag, cmd, cmdLen);
}

int tlvSet_u8bufOptional_ByteShift(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    int ret = 1;
    if (cmdLen == 0) {
        ret = 0;
    }
    else if (0 == (cmdLen & 1)) {
        /* LSB is 0 */
        ret = tlvSet_u8buf(buf, bufLen, tag, cmd, cmdLen);
    }
    else {
        uint8_t localBuff[SE05X_MAX_BUF_SIZE_CMD];
        ENSURE_OR_GO_CLEANUP((cmdLen + 1) < sizeof(localBuff));
        localBuff[0] = '\0';
        memcpy(localBuff + 1, cmd, cmdLen);
        ret = tlvSet_u8buf(buf, bufLen, tag, localBuff, cmdLen + 1);
    }

cleanup:
    return ret;
}

int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = *buf;

    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFf ? 2 : 3));
    const size_t size_of_tlv    = 1 + size_of_length + cmdLen;

    if (((*bufLen) + size_of_tlv) > SE05X_TLV_BUF_SIZE_CMD) {
        LOG_E("Not enough buffer");
        return 1;
    }
    *pBuf++ = (uint8_t)tag;

    if (cmdLen <= 0x7Fu) {
        *pBuf++ = (uint8_t)cmdLen;
    }
    else if (cmdLen <= 0xFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if (cmdLen) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *bufLen += size_of_tlv;
    *buf = pBuf;

    return 0;
}

int tlvSet_u8buf_features(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, pSe05xAppletFeatures_t appletVariant)
{
    uint8_t features[32] = {0};
    size_t features_size = 0;
    features[0]          = (uint8_t)((appletVariant->variant >> 1 * 8) & 0xFF);
    features_size++;
    features[1] = (uint8_t)((appletVariant->variant >> 0 * 8) & 0xFF);
    features_size++;
    if (appletVariant->extended_features) {
        memcpy(&features[2],
            appletVariant->extended_features->features,
            sizeof(appletVariant->extended_features->features));
        features_size += sizeof(appletVariant->extended_features->features);
    }

    return tlvSet_u8buf(buf, bufLen, tag, &features[0], features_size);
}

int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t rspLen;
    if (got_tag != tag)
        goto cleanup;
    rspLen = *pBuf++;
    if (rspLen > 1)
        goto cleanup;
    *pRsp = *pBuf;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

int tlvSet_KeyID(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t keyID)
{
    int retVal = 0;
    if (keyID != 0) {
        retVal = tlvSet_U32(buf, bufLen, tag, keyID);
    }
    return retVal;
}

int tlvSet_MaxAttemps(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t maxAttemps)
{
    int retVal = 0;
    if (maxAttemps != 0) {
        retVal = tlvSet_U16(buf, bufLen, tag, maxAttemps);
    }
    return retVal;
}

int tlvGet_SecureObjectType(uint8_t *buf, size_t *pBufIndex, size_t bufLen, SE05x_TAG_t tag, SE05x_SecObjTyp_t *pType)
{
    uint8_t uType = 0;
    int retVal    = tlvGet_U8(buf, pBufIndex, bufLen, tag, &uType);
    *pType        = uType;
    return retVal;
}

int tlvGet_Result(uint8_t *buf, size_t *pBufIndex, size_t bufLen, SE05x_TAG_t tag, SE05x_Result_t *presult)
{
    uint8_t uType   = 0;
    size_t uTypeLen = 1;
    int retVal      = tlvGet_u8buf(buf, pBufIndex, bufLen, tag, &uType, &uTypeLen);
    *presult        = uType;
    return retVal;
}

int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint16_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t rspLen;
    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 2) {
        goto cleanup;
    }
    *pRsp = (*pBuf++) << 8;
    *pRsp |= *pBuf++;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

//ISO 7816-4 Annex D.
int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;
    if (got_tag != tag)
        goto cleanup;
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > *pRspLen)
        goto cleanup;
    if (extendedLen > bufLen)
        goto cleanup;

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    return retVal;
}

int tlvGet_TimeStamp(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, SE05x_TimeStamp_t *pTs)
{
    size_t rspBufSize = sizeof(pTs->ts);
    return tlvGet_u8buf(buf, pBufIndex, bufLen, tag, pTs->ts, &rspBufSize);
}

smStatus_t DoAPDUTx_s_Case3(Se05xSession_t *pSessionCtx, const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen)
{
    uint8_t rxBuf[SE05X_TLV_BUF_SIZE_RSP + 2];
    size_t rxBufLen       = sizeof(rxBuf);
    smStatus_t apduStatus = 0;
    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, hdr, cmdBuf, cmdBufLen, rxBuf, &rxBufLen, 0);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case2(Se05xSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen)
{
    smStatus_t apduStatus;
    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, hdr, cmdBuf, cmdBufLen, rspBuf, pRspBufLen, 0);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case4(Se05xSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen)
{
    smStatus_t apduStatus;
    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, hdr, cmdBuf, cmdBufLen, rspBuf, pRspBufLen, 0);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx_s_Case4_ext(Se05xSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen)
{
    smStatus_t apduStatus = 0;
    if (pSessionCtx->fp_TXn == NULL) {
        apduStatus = SM_NOT_OK;
    }
    else {
        apduStatus = pSessionCtx->fp_TXn(pSessionCtx, hdr, cmdBuf, cmdBufLen, rspBuf, pRspBufLen, 1);
    }
    return apduStatus;
}

smStatus_t DoAPDUTxRx(
    Se05xSession_t *pSessionCtx, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen)
{
    smStatus_t apduStatus     = SM_NOT_OK;
    size_t data_offset        = 0;
    size_t dataLen            = 0;
    apduTxRx_case_t apdu_case = APDU_TXRX_CASE_INVALID;

    if (smApduGetTxRxCase(cmdBuf, cmdBufLen, &data_offset, &dataLen, &apdu_case)) {
        switch (apdu_case) {
        case APDU_TXRX_CASE_1:
        case APDU_TXRX_CASE_2:
        case APDU_TXRX_CASE_2E:
            apduStatus = DoAPDUTxRx_s_Case2(
                pSessionCtx, (tlvHeader_t *)cmdBuf, cmdBuf + data_offset, dataLen, rspBuf, pRspBufLen);
            break;
        case APDU_TXRX_CASE_3:
		case APDU_TXRX_CASE_4:
			// Using case 4 here (also for case 3 apdus) to retrieve status word in response buffer.
			apduStatus = DoAPDUTxRx_s_Case4(
				pSessionCtx, (tlvHeader_t *)cmdBuf, cmdBuf + data_offset, dataLen, rspBuf, pRspBufLen);
			break;

		case APDU_TXRX_CASE_3E:
        case APDU_TXRX_CASE_4E:
			// Using case 4 here (also for case 3 apdus) to retrieve status word in response buffer.
			apduStatus = DoAPDUTxRx_s_Case4_ext(
                pSessionCtx, (tlvHeader_t *)cmdBuf, cmdBuf + data_offset, dataLen, rspBuf, pRspBufLen);
            break;
        default:
            LOG_E("Invalid APDU TxRX case");
            break;
        }
    }
    return apduStatus;
}

#if SSS_HAVE_SE05X
int tlvSet_u8buf_I2CM(uint8_t **buf, size_t *bufLen, SE05x_I2CM_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = 2;
    const size_t size_of_tlv    = 1 + size_of_length + cmdLen;
    uint8_t *pBuf               = *buf;
    if (((*bufLen) + size_of_tlv) > SE05X_I2CM_MAX_BUF_SIZE_CMD) {
        LOG_E("Not enough buffer");
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if (cmdLen) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
        *buf = pBuf;
        *bufLen += size_of_tlv;
    }
    return 0;
}
#endif

smStatus_t se05x_Transform(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdApduBuf,
    const size_t cmdApduBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasle)
{
    size_t i = 0;

    out_hdr->hdr[0] = hdr->hdr[0];
    out_hdr->hdr[1] = hdr->hdr[1];
    out_hdr->hdr[2] = hdr->hdr[2];
    out_hdr->hdr[3] = hdr->hdr[3];

    if (pSession->hasSession) {
#if SSSFTR_SE05X_AuthECKey || SSSFTR_SE05X_AuthSession

        size_t SCmd_Lc = (cmdApduBufLen == 0) ? 0 : (((cmdApduBufLen < 0xFF) && !hasle) ? 1 : 3);

        size_t STag1_Len = 0
                           /* cla ins */
                           + 4 + SCmd_Lc + cmdApduBufLen;

        out_hdr->hdr[i++] = kSE05x_CLA;
        out_hdr->hdr[i++] = kSE05x_INS_PROCESS;
        out_hdr->hdr[i++] = kSE05x_P1_DEFAULT;
        out_hdr->hdr[i++] = kSE05x_P2_DEFAULT;

        i          = 0;
        txBuf[i++] = kSE05x_TAG_SESSION_ID;
        txBuf[i++] = sizeof(pSession->value);
        memcpy(&txBuf[i], pSession->value, sizeof(pSession->value));
        i += sizeof(pSession->value);
        txBuf[i++] = kSE05x_TAG_1;
        if (STag1_Len <= 0x7Fu) {
            txBuf[i++] = (uint8_t)STag1_Len;
        }
        else if (STag1_Len <= 0xFFu) {
            txBuf[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
            txBuf[i++] = (uint8_t)((STag1_Len >> 0 * 8) & 0xFF);
        }
        else if (STag1_Len <= 0xFFFFu) {
            txBuf[i++] = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
            txBuf[i++] = (uint8_t)((STag1_Len >> 8) & 0xFF);
            txBuf[i++] = (uint8_t)((STag1_Len)&0xFF);
        }
        memcpy(&txBuf[i], hdr, sizeof(*hdr));
        i += sizeof(*hdr);
        // In case there is a payload, indicate how long it is
        // in Lc in the header. Do not include an Lc in case there
        //is no payload.
        if (cmdApduBufLen > 0) {
            // The Lc field must be extended in case the length does not fit
            // into a single byte (Note, while the standard would allow to
            // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
            // would actually do that).
            if ((cmdApduBufLen < 0xFF) && !hasle) {
                txBuf[i++] = (uint8_t)cmdApduBufLen;
            }
            else {
                txBuf[i++] = 0x00;
                txBuf[i++] = 0xFFu & (cmdApduBufLen >> 8);
                txBuf[i++] = 0xFFu & (cmdApduBufLen);
            }
        }
#endif
    }

    if (cmdApduBufLen > 0) {
        memcpy(&txBuf[i], cmdApduBuf, cmdApduBufLen);
        i += cmdApduBufLen;
    }

    *ptxBufLen = i;
    return SM_OK;
}

smStatus_t se05x_DeCrypt(
    struct Se05xSession *pSessionCtx, size_t cmd_cmacLen, uint8_t *rsp, size_t *rspLength, uint8_t hasle)
{
    U16 rv = SM_NOT_OK;

    if (*rspLength >= 2) {
        rv = rsp[(*rspLength) - 2] << 8 | rsp[(*rspLength) - 1];
        if ((rv == SM_OK) && (pSessionCtx->pdynScp03Ctx != NULL)) {
#if SSS_HAVE_SCP_SCP03_SSS
            rv = nxpSCP03_Decrypt_ResponseAPDU(pSessionCtx->pdynScp03Ctx, cmd_cmacLen, rsp, rspLength, hasle);
#else
            LOG_W("Decrypting without SSS_HAVE_SCP_SCP03_SSS");
            rv = SM_NOT_OK;
#endif
        }
#if SSS_HAVE_SCP_SCP03_SSS
        else { /*Counter to be increament only in case of authentication is all kind of SCP
              and response is not 9000 */
            if ((rv != SM_OK) && (pSessionCtx->pdynScp03Ctx != NULL)) {
                if (((pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_AESKey) ||
                        (pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_ECKey)) ||
                    ((pSessionCtx->pdynScp03Ctx->authType == kSSS_AuthType_SCP03) && (cmd_cmacLen - 8) > 0)) {
                    nxpSCP03_Inc_CommandCounter(pSessionCtx->pdynScp03Ctx);
                }
            }
        }
#endif
    }
    else {
        rv = SM_NOT_OK;
    }

    return rv;
}

#if SSS_HAVE_SCP_SCP03_SSS
smStatus_t se05x_Transform_scp(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdApduBuf,
    const size_t cmdApduBufLen,
    tlvHeader_t *outhdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasle)
{
    smStatus_t apduStatus   = SM_NOT_OK;
    sss_status_t sss_status = kStatus_SSS_Fail;
    uint8_t macToAdd[16];
    size_t macLen = 16;
    int i         = 0;

    Se05xApdu_t se05xApdu = {0};

    se05xApdu.se05xTxBuf    = txBuf;
    se05xApdu.se05xTxBufLen = *ptxBufLen;
    se05xApdu.se05xCmd_hdr  = hdr;
    se05xApdu.se05xCmd      = cmdApduBuf;
    se05xApdu.se05xCmdLen   = cmdApduBufLen;

    /*Encrypt the Tx APDU */
    sss_status = nxSCP03_Encrypt_CommandAPDU(pSession->pdynScp03Ctx, se05xApdu.se05xCmd, &(se05xApdu.se05xCmdLen));
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);

    if (pSession->hasSession) {
#if SSSFTR_SE05X_AuthECKey || SSSFTR_SE05X_AuthSession
        /*With session Final wrapping handled by transcive
        * Copy the Wrapped header in the outhdr buffer */
        outhdr->hdr[0] = kSE05x_CLA;
        outhdr->hdr[1] = kSE05x_INS_PROCESS;
        outhdr->hdr[2] = kSE05x_P1_DEFAULT;
        outhdr->hdr[3] = kSE05x_P2_DEFAULT;

        /* Add CMAC Length in SE05X command LC */
        se05xApdu.se05xCmdLC  = se05xApdu.se05xCmdLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
        se05xApdu.se05xCmdLCW = (se05xApdu.se05xCmdLC == 0) ? 0 : (((se05xApdu.se05xCmdLC < 0xFF) && !(hasle)) ? 1 : 3);

        se05xApdu.wsSe05x_tag1Len = sizeof(*(se05xApdu.se05xCmd_hdr)) + se05xApdu.se05xCmdLCW + se05xApdu.se05xCmdLC;
        se05xApdu.wsSe05x_tag1W =
            ((se05xApdu.wsSe05x_tag1Len <= 0x7F) ? 1 : (se05xApdu.wsSe05x_tag1Len <= 0xFF) ? 2 : 3);

        se05xApdu.wsSe05x_cmd = se05xApdu.se05xTxBuf;
        uint8_t *wsCmd        = se05xApdu.wsSe05x_cmd;

        wsCmd[i++] = kSE05x_TAG_SESSION_ID;
        wsCmd[i++] = sizeof(pSession->value);
        memcpy(&wsCmd[i], pSession->value, sizeof(pSession->value));
        i += sizeof(pSession->value);

        wsCmd[i++] = kSE05x_TAG_1;

        if (se05xApdu.wsSe05x_tag1W == 1) {
            wsCmd[i++] = (uint8_t)se05xApdu.wsSe05x_tag1Len;
        }
        else if (se05xApdu.wsSe05x_tag1W == 2) {
            wsCmd[i++] = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
            wsCmd[i++] = (uint8_t)((se05xApdu.wsSe05x_tag1Len >> 0 * 8) & 0xFF);
        }
        else if (se05xApdu.wsSe05x_tag1W == 3) {
            wsCmd[i++] = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
            wsCmd[i++] = (uint8_t)((se05xApdu.wsSe05x_tag1Len >> 8) & 0xFF);
            wsCmd[i++] = (uint8_t)((se05xApdu.wsSe05x_tag1Len) & 0xFF);
        }

        se05xApdu.wsSe05x_tag1Cmd = &wsCmd[i];
        se05xApdu.wsSe05x_tag1CmdLen =
            sizeof(*(se05xApdu.se05xCmd_hdr)) + se05xApdu.se05xCmdLCW + se05xApdu.se05xCmdLen;

        memcpy(&wsCmd[i], se05xApdu.se05xCmd_hdr, sizeof(*(se05xApdu.se05xCmd_hdr)));
        /* Pad CLA byte with 0x04 to indicate use of SCP03*/
        wsCmd[i] |= 0x04;
        i += sizeof(*(se05xApdu.se05xCmd_hdr));

        // In case there is a payload, indicate how long it is
        // in Lc in the header. Do not include an Lc in case there
        //is no payload.
        if (se05xApdu.se05xCmdLCW > 0) {
            // The Lc field must be extended in case the length does not fit
            // into a single byte (Note, while the standard would allow to
            // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
            // would actually do that).
            if (se05xApdu.se05xCmdLCW == 1) {
                wsCmd[i++] = (uint8_t)se05xApdu.se05xCmdLC;
            }
            else {
                wsCmd[i++] = 0x00;
                wsCmd[i++] = 0xFFu & (se05xApdu.se05xCmdLC >> 8);
                wsCmd[i++] = 0xFFu & (se05xApdu.se05xCmdLC);
            }
        }
        memcpy(&wsCmd[i], se05xApdu.se05xCmd, se05xApdu.se05xCmdLen);
        i += se05xApdu.se05xCmdLen;
        se05xApdu.wsSe05x_cmdLen = i;
        se05xApdu.dataToMac      = se05xApdu.wsSe05x_tag1Cmd;
        se05xApdu.dataToMacLen   = se05xApdu.wsSe05x_tag1CmdLen;
#endif
    }
    else {
        /* If there is no session create the tx buffer with SE05X command only*/
        se05xApdu.se05xCmdLC  = se05xApdu.se05xCmdLen + SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
        se05xApdu.se05xCmdLCW = (se05xApdu.se05xCmdLC == 0) ? 0 : (((se05xApdu.se05xCmdLC < 0xFF) && !(hasle)) ? 1 : 3);

        se05xApdu.dataToMac    = &txBuf[i]; /* Mac is calculated from this data */
        se05xApdu.dataToMacLen = sizeof(*(se05xApdu.se05xCmd_hdr)) + se05xApdu.se05xCmdLCW + se05xApdu.se05xCmdLC -
                                 SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

        memcpy(&txBuf[i], se05xApdu.se05xCmd_hdr, sizeof(*se05xApdu.se05xCmd_hdr));
        txBuf[i] |= 0x4;
        i += sizeof(*se05xApdu.se05xCmd_hdr);

        if (se05xApdu.se05xCmdLCW > 0) {
            if (se05xApdu.se05xCmdLCW == 1) {
                txBuf[i++] = (uint8_t)se05xApdu.se05xCmdLC;
            }
            else {
                txBuf[i++] = 0x00;
                txBuf[i++] = 0xFFu & (se05xApdu.se05xCmdLC >> 8);
                txBuf[i++] = 0xFFu & (se05xApdu.se05xCmdLC);
            }
        }
        memcpy(&txBuf[i], se05xApdu.se05xCmd, se05xApdu.se05xCmdLen);
        i += se05xApdu.se05xCmdLen;
    }

    ///*Calculate MAC over encrypted APDU */
    sss_status = nxpSCP03_CalculateMac_CommandAPDU(
        pSession->pdynScp03Ctx, se05xApdu.dataToMac, se05xApdu.dataToMacLen, macToAdd, &macLen);
    ENSURE_OR_GO_CLEANUP(sss_status == kStatus_SSS_Success);
    memcpy(&txBuf[i], macToAdd, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    i += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    if (!pSession->hasSession) {
        if (hasle) {
            txBuf[i++] = 0x00;
            txBuf[i++] = 0x00;
        }
    }
    se05xApdu.se05xTxBufLen = i;
    *ptxBufLen              = se05xApdu.se05xTxBufLen;
    apduStatus              = SM_OK;
cleanup:
    return apduStatus;
}

#endif
