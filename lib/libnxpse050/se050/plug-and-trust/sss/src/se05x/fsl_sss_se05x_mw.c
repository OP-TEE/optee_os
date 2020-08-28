/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#include <fsl_sss_se05x_apis.h>
#include <nxLog_sss.h>

#if SSS_HAVE_APPLET_SE05X_IOT
#include <Applet_SE050_Ver.h>
#include <se05x_APDU.h>
#include <se05x_const.h>
#include <se05x_tlv.h>
#include <string.h>

uint32_t se05x_sssKeyTypeLenToCurveId(sss_cipher_type_t cipherType, size_t keyBits)
{
    uint32_t u32_curve_id = 0;
    switch (cipherType) {
    case kSSS_CipherType_EC_NIST_P: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
        case 192:
            eCurveID = kSE05x_ECCurve_NIST_P192;
            break;
        case 224:
            eCurveID = kSE05x_ECCurve_NIST_P224;
            break;
        case 256:
            eCurveID = kSE05x_ECCurve_NIST_P256;
            break;
        case 384:
            eCurveID = kSE05x_ECCurve_NIST_P384;
            break;
        case 521:
            eCurveID = kSE05x_ECCurve_NIST_P521;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_BRAINPOOL: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
        case 160:
            eCurveID = kSE05x_ECCurve_Brainpool160;
            break;
        case 192:
            eCurveID = kSE05x_ECCurve_Brainpool192;
            break;
        case 224:
            eCurveID = kSE05x_ECCurve_Brainpool224;
            break;
        case 256:
            eCurveID = kSE05x_ECCurve_Brainpool256;
            break;
        case 320:
            eCurveID = kSE05x_ECCurve_Brainpool320;
            break;
        case 384:
            eCurveID = kSE05x_ECCurve_Brainpool384;
            break;
        case 512:
            eCurveID = kSE05x_ECCurve_Brainpool512;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_NIST_K: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
        case 160:
            eCurveID = kSE05x_ECCurve_Secp160k1;
            break;
        case 192:
            eCurveID = kSE05x_ECCurve_Secp192k1;
            break;
        case 224:
            eCurveID = kSE05x_ECCurve_Secp224k1;
            break;
        case 256:
            eCurveID = kSE05x_ECCurve_Secp256k1;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_MONTGOMERY: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
#if SSS_HAVE_SE05X_VER_GTE_04_04
        case 448:
            eCurveID = kSE05x_ECCurve_RESERVED_ID_ECC_MONT_DH_448;
            break;
#endif
        case 256:
            eCurveID = kSE05x_ECCurve_RESERVED_ID_ECC_MONT_DH_25519;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_TWISTED_ED: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
        case 256:
            eCurveID = kSE05x_ECCurve_RESERVED_ID_ECC_ED_25519;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_BARRETO_NAEHRIG: {
        SE05x_ECCurve_t eCurveID;
        switch (keyBits) {
        case 256:
            eCurveID = kSE05x_ECCurve_TPM_ECC_BN_P256;
            break;
        default:
            eCurveID = 0;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    default:
        break;
    }
    return u32_curve_id;
}

smStatus_t Se05x_API_EC_CurveGetId(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_ECCurve_t *pcurveId)
{
    smStatus_t ret = SM_NOT_OK;
    if (pcurveId) {
        uint8_t u8curve = 0;
        ret             = Se05x_API_GetECCurveId(session_ctx, objectID, &u8curve);
        if (ret == SM_OK) {
            *pcurveId = (SE05x_ECCurve_t)u8curve;
        }
    }
    return ret;
}

smStatus_t Se05x_i2c_master_txn(sss_session_t *sess, SE05x_I2CM_cmd_t *p, uint8_t noOftags)
{
    smStatus_t retval                              = SM_NOT_OK;
    uint8_t buffer[SE05X_I2CM_MAX_BUF_SIZE_CMD]    = {0};
    size_t bufferLen                               = 0;
    uint8_t iCnt                                   = 0;
    uint8_t remainingCnt                           = 0;
    int tlvRet                                     = 0;
    uint8_t rspbuffer[SE05X_I2CM_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufferLen                            = sizeof(rspbuffer);

    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)sess;
    Se05xSession_t *se050session_id    = NULL;

    uint8_t *pCmdbuf        = &buffer[0];
    const uint8_t *pSendbuf = &buffer[0];
    size_t SendLen          = 0;

    if (se05x_session->subsystem == kType_SSS_SE_SE05x) {
        se050session_id = &se05x_session->s_ctx;
    }
    else {
        goto cleanup;
    }

    for (iCnt = 0; iCnt < noOftags; iCnt++) {
        if (p[iCnt].type == kSE05x_I2CM_Configure) {
            uint8_t configBuf[2] = {0};
            size_t configBufLen  = sizeof(configBuf);
            configBuf[0]         = p[iCnt].cmd.cfg.I2C_addr;
            configBuf[1]         = p[iCnt].cmd.cfg.I2C_baudRate;
            tlvRet               = TLVSET_u8buf_I2CM(
                "I2CM Configure", &pCmdbuf, &bufferLen, kSE05x_TAG_I2CM_Config, configBuf, configBufLen);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        //else if (p[iCnt].type == kSE05x_I2CM_Security) {
        //}
        else if (p[iCnt].type == kSE05x_I2CM_Write) {
            tlvRet = TLVSET_u8buf_I2CM("I2CM Write",
                &pCmdbuf,
                &bufferLen,
                kSE05x_TAG_I2CM_Write,
                p[iCnt].cmd.w.writebuf,
                p[iCnt].cmd.w.writeLength);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        else if (p[iCnt].type == kSE05x_I2CM_Read) {
            uint8_t readLenBuf[2];
            size_t readLenBufLen = sizeof(readLenBuf);
            readLenBuf[0]        = (uint8_t)(p[iCnt].cmd.rd.readLength >> 8);
            readLenBuf[1]        = (uint8_t)(p[iCnt].cmd.rd.readLength);
            tlvRet =
                TLVSET_u8buf_I2CM("I2CM Read", &pCmdbuf, &bufferLen, kSE05x_TAG_I2CM_Read, readLenBuf, readLenBufLen);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        else {
            break;
        }
    }

    SendLen = bufferLen;
    retval  = Se05x_API_I2CM_Send(se050session_id, pSendbuf, SendLen, rspbuffer, &rspbufferLen);

    if (retval == SM_OK) {
        // Walk through the result.
        // In principle the order of results matches the order the incoming commands.
        // Exception: Structural error in format incoming commands
        uint8_t *rspTag     = &rspbuffer[0];
        unsigned int rspPos = 1u;
        for (iCnt = 0; iCnt < noOftags; iCnt++) {
            if (*rspTag == kSE05x_I2CM_StructuralIssue) {
                // Modify TLV type of command to report back error
                p[iCnt].type                  = kSE05x_I2CM_StructuralIssue;
                p[iCnt].cmd.issue.issueStatus = rspbuffer[rspPos];
                break;
            }
            else if (p[iCnt].type == kSE05x_I2CM_Configure) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.cfg.status = rspbuffer[rspPos];
            }
            //else if (p[iCnt].type == kSE05x_I2CM_Security) {
            //}
            else if (p[iCnt].type == kSE05x_I2CM_Write) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.w.wrStatus = rspbuffer[rspPos];
            }
            else if (p[iCnt].type == kSE05x_I2CM_Read) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.rd.rdStatus = rspbuffer[rspPos];
                if (p[iCnt].cmd.rd.rdStatus == kSE05x_I2CM_Success) {
                    // Receiving less data than requested is not considered an error
                    uint16_t reportedRead = (rspbuffer[rspPos + 1] << 8) + rspbuffer[rspPos + 2];
                    rspPos += 2;
                    if (reportedRead < p[iCnt].cmd.rd.readLength) {
                        LOG_W("kSE05x_I2CM_Read: Requested %d, Received %d byte",
                            p[iCnt].cmd.rd.readLength,
                            reportedRead);
                        p[iCnt].cmd.rd.readLength = reportedRead;
                    }
                    // Did we receive enough data?
                    if (rspbufferLen > (rspPos + p[iCnt].cmd.rd.readLength)) {
                        memcpy(p[iCnt].cmd.rd.rdBuf, &rspbuffer[rspPos + 1], p[iCnt].cmd.rd.readLength);
                        rspPos += p[iCnt].cmd.rd.readLength;
                    }
                    else {
                        // TODO: Indicate we could not transfer result into buffer
                        LOG_E(
                            "kSE05x_I2CM_Read: Expecting more data (%d) than "
                            "was received",
                            p[iCnt].cmd.rd.readLength);
                        break;
                    }
                }
            }
            else {
                break;
            }
            // Update parsing position
            if (rspbufferLen > rspPos + 2u) {
                rspTag = &rspbuffer[rspPos + 1];
                rspPos += 2;
            }
        }
        // If we dropped out before handling all tags, clear the tagtype of the tags
        // that were not handled
        for (remainingCnt = iCnt + 1; remainingCnt < noOftags; remainingCnt++) {
            p[remainingCnt].type = kSE05x_I2CM_None;
        }
    }

cleanup:
    return retval;
}

smStatus_t Se05x_i2c_master_attst_txn(sss_session_t *sess,
    sss_object_t *keyObject,
    SE05x_I2CM_cmd_t *p,
    uint8_t *random_attst,
    size_t random_attstLen,
    SE05x_AttestationAlgo_t attst_algo,
    SE05x_TimeStamp_t *ptimeStamp,
    size_t *timeStampLen,
    uint8_t *freshness,
    size_t *pfreshnessLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen,
    uint8_t noOftags)
{
    smStatus_t retval                              = SM_NOT_OK;
    uint8_t buffer[SE05X_I2CM_MAX_BUF_SIZE_CMD]    = {0};
    size_t bufferLen                               = 0;
    uint8_t iCnt                                   = 0;
    uint8_t remainingCnt                           = 0;
    int tlvRet                                     = 0;
    uint8_t rspbuffer[SE05X_I2CM_MAX_BUF_SIZE_RSP] = {0};
    size_t rspbufferLen                            = sizeof(rspbuffer);
    uint32_t attestID;

    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)sess;
    Se05xSession_t *se050session_id    = NULL;

    sss_se05x_object_t *keyObject_attst = (sss_se05x_object_t *)keyObject;
    attestID                            = keyObject_attst->keyId;

    uint8_t *pCmdbuf        = &buffer[0];
    const uint8_t *pSendbuf = &buffer[0];
    size_t SendLen          = 0;

    if (se05x_session->subsystem == kType_SSS_SE_SE05x) {
        se050session_id = &se05x_session->s_ctx;
    }
    else {
        goto cleanup;
    }

    for (iCnt = 0; iCnt < noOftags; iCnt++) {
        if (p[iCnt].type == kSE05x_I2CM_Configure) {
            uint8_t configBuf[2] = {0};
            size_t configBufLen  = sizeof(configBuf);
            configBuf[0]         = p[iCnt].cmd.cfg.I2C_addr;
            configBuf[1]         = p[iCnt].cmd.cfg.I2C_baudRate;
            tlvRet               = TLVSET_u8buf_I2CM(
                "I2CM Configure", &pCmdbuf, &bufferLen, kSE05x_TAG_I2CM_Config, configBuf, configBufLen);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        else if (p[iCnt].type == kSE05x_I2CM_Write) {
            tlvRet = TLVSET_u8buf_I2CM("I2CM Write",
                &pCmdbuf,
                &bufferLen,
                kSE05x_TAG_I2CM_Write,
                p[iCnt].cmd.w.writebuf,
                p[iCnt].cmd.w.writeLength);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        else if (p[iCnt].type == kSE05x_I2CM_Read) {
            uint8_t readLenBuf[2];
            size_t readLenBufLen = sizeof(readLenBuf);
            readLenBuf[0]        = (uint8_t)(p[iCnt].cmd.rd.readLength >> 8);
            readLenBuf[1]        = (uint8_t)(p[iCnt].cmd.rd.readLength);
            tlvRet =
                TLVSET_u8buf_I2CM("I2CM Read", &pCmdbuf, &bufferLen, kSE05x_TAG_I2CM_Read, readLenBuf, readLenBufLen);
            if (0 != tlvRet) {
                goto cleanup;
            }
        }
        else {
            break;
        }
    }
    *timeStampLen = sizeof(SE05x_TimeStamp_t);
    SendLen       = bufferLen;
    retval        = Se05x_API_I2CM_ExecuteCommandSet(se050session_id,
        pSendbuf,
        SendLen,
        attestID,
        attst_algo,
        rspbuffer,
        &rspbufferLen,
        ptimeStamp,
        freshness,
        pfreshnessLen,
        chipId,
        pchipIdLen,
        signature,
        psignatureLen,
        random_attst,
        random_attstLen);

    if (retval == SM_OK) {
        // Walk through the result.
        // In principle the order of results matches the order the incoming commands.
        // Exception: Structural error in format incoming commands
        uint8_t *rspTag     = &rspbuffer[0];
        unsigned int rspPos = 1u;
        for (iCnt = 0; iCnt < noOftags; iCnt++) {
            if (*rspTag == kSE05x_I2CM_StructuralIssue) {
                // Modify TLV type of command to report back error
                p[iCnt].type                  = kSE05x_I2CM_StructuralIssue;
                p[iCnt].cmd.issue.issueStatus = rspbuffer[rspPos];
                break;
            }
            else if (p[iCnt].type == kSE05x_I2CM_Configure) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.cfg.status = rspbuffer[rspPos];
            }
            //else if (p[iCnt].type == kSE05x_I2CM_Security) {
            //}
            else if (p[iCnt].type == kSE05x_I2CM_Write) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.w.wrStatus = rspbuffer[rspPos];
            }
            else if (p[iCnt].type == kSE05x_I2CM_Read) {
                // Check whether response is in expected order
                if (*rspTag != p[iCnt].type) {
                    LOG_W("Response out-of-order");
                    break;
                }
                p[iCnt].cmd.rd.rdStatus = rspbuffer[rspPos];
                if (p[iCnt].cmd.rd.rdStatus == kSE05x_I2CM_Success) {
                    // Receiving less data than requested is not considered an error
                    uint16_t reportedRead = (rspbuffer[rspPos + 1] << 8) + rspbuffer[rspPos + 2];
                    rspPos += 2;
                    if (reportedRead < p[iCnt].cmd.rd.readLength) {
                        LOG_W("kSE05x_I2CM_Read: Requested %d, Received %d byte",
                            p[iCnt].cmd.rd.readLength,
                            reportedRead);
                        p[iCnt].cmd.rd.readLength = reportedRead;
                    }
                    // Did we receive enough data?
                    if (rspbufferLen > (rspPos + p[iCnt].cmd.rd.readLength)) {
                        memcpy(p[iCnt].cmd.rd.rdBuf, &rspbuffer[rspPos + 1], p[iCnt].cmd.rd.readLength);
                        rspPos += p[iCnt].cmd.rd.readLength;
                    }
                    else {
                        // TODO: Indicate we could not transfer result into buffer
                        LOG_E(
                            "kSE05x_I2CM_Read: Expecting more data (%d) than "
                            "was received",
                            p[iCnt].cmd.rd.readLength);
                        break;
                    }
                }
            }
            else {
                break;
            }
            // Update parsing position
            if (rspbufferLen > rspPos + 2u) {
                rspTag = &rspbuffer[rspPos + 1];
                rspPos += 2;
            }
        }
        // If we dropped out before handling all tags, clear the tagtype of the tags
        // that were not handled
        for (remainingCnt = iCnt + 1; remainingCnt < noOftags; remainingCnt++) {
            p[remainingCnt].type = kSE05x_I2CM_None;
        }
    }

cleanup:
    return retval;
}

#endif /* SSS_HAVE_APPLET_SE05X_IOT */
