/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *
 * @par Description
 * This file implements the high-level APDU handling of the SM module.
 * @par History
 * 1.0   31-march-2014 : Initial version
 * 1.1   10-april-2019 : Removed compile time choice 'USE_MALLOC_FOR_APDU_BUFFER'
 *
 *****************************************************************************/
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "sm_apdu.h"
// #include "ax_api.h"
#include "scp.h"
#include "nxLog_hostLib.h"
#include "nxEnsure.h"

static void ReserveLc(apdu_t * pApdu);
static void SetLc(apdu_t * pApdu, U16 lc);
static void AddLe(apdu_t * pApdu, U16 le);

#if SSS_HAVE_A71CH_SIM
/* Send session ID in trans-receive */
static U8 session_Tlv[7];
static U8 gEnableEnc = 0;
#endif

static U8 sharedApduBuffer[MAX_APDU_BUF_LENGTH];

#ifdef TGT_A71CH
#if ( (APDU_HEADER_LENGTH + APDU_STD_MAX_DATA + 1) >= MAX_APDU_BUF_LENGTH )
#error "Ensure MAX_APDU_BUF_LENGTH is big enough"
#endif
#endif // TGT_A71CH

/**
 * Associates a memory buffer with the APDU buffer.
 *
 * By default (determined at compile time) the buffer is not allocated with each call, but a reference
 * is made to a static data structure.
 *
 * \param[in,out] pApdu         APDU buffer
 * \returns always returns 0
 */
U8 AllocateAPDUBuffer(apdu_t *pApdu)
{
    ENSURE_OR_GO_EXIT(pApdu != NULL);
    // In case of e.g. TGT_A7, pApdu is pointing to a structure defined on the stack
    // so pApdu->pBuf contains random data
    pApdu->pBuf = sharedApduBuffer;

exit:
    return 0;
}

/**
 * Clears the previously referenced APDU buffer.
 *
 * In case the buffer was effectively malloc'd by ::AllocateAPDUBuffer it will also be freed.
 *
 * \param[in,out] pApdu              APDU buffer
 * \return Always returns 0
 */
U8 FreeAPDUBuffer(apdu_t * pApdu)
{
    ENSURE_OR_GO_EXIT(pApdu != NULL);

    if (pApdu->pBuf)
    {
        U16 nClear = (pApdu->rxlen > MAX_APDU_BUF_LENGTH) ? MAX_APDU_BUF_LENGTH : pApdu->rxlen;
        memset(pApdu->pBuf, 0, nClear);
        pApdu->pBuf = 0;
    }

exit:
    return 0;
}

/**
 * Sets up the command APDU header.
 * \param[in,out] pApdu      APDU buffer
 * \param[in] extendedLength Indicates if command/response have extended length. Either ::USE_STANDARD_APDU_LEN or ::USE_EXTENDED_APDU_LEN
 * \return                   offset in APDU buffer after the header
 */
U8 SetApduHeader(apdu_t * pApdu, U8 extendedLength)
{
    U8 ret = 0;
    //    pApdu->edc = eEdc_NoErrorDetection;
    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->pBuf[0] = pApdu->cla;
    pApdu->pBuf[1] = pApdu->ins;
    pApdu->pBuf[2] = pApdu->p1;
    pApdu->pBuf[3] = pApdu->p2;

    pApdu->extendedLength = extendedLength;
    pApdu->hasData = false;
    pApdu->lcLength = 0;
    pApdu->lc = 0;
    pApdu->hasLe = false;

    // No LC yet
    pApdu->offset = APDU_OFFSET_LC;

    // adapt length
    pApdu->buflen = pApdu->offset;

    // Set rxlen to default value
    pApdu->rxlen = 0;

    ret = (U8)(pApdu->offset);
exit:
    return ret;
}

#if SSS_HAVE_A71CH_SIM
/**
 * Creates session TLV from session ID. Session ID is retrieved as response to auth command.
 * \param[in] sessionId
 */
void set_SessionId_Tlv(U32 sessionId)
{
    session_Tlv[0] = 0xBE;
    session_Tlv[1] = 0xBE;
    session_Tlv[2] = 0x04;
    session_Tlv[3] = (U8)(sessionId >> 24);
    session_Tlv[4] = (U8)(sessionId >> 16);
    session_Tlv[5] = (U8)(sessionId >> 8);
    session_Tlv[6] = (U8)(sessionId >> 0);
    gEnableEnc = sessionId !=0 ? 1:0;
}
#endif

/**
 * In the final stage before sending the APDU cmd one needs to update the values of lc (and le).
 * \param[in,out] pApdu        APDU buffer
 * \param[in] lc
 */
void smApduAdaptLc(apdu_t *pApdu, U16 lc)
{
    SetLc(pApdu, lc);
}

/**
 * In the final stage before sending the APDU cmd one needs to update the values of le (and lc).
 * \param[in,out] pApdu        APDU buffer
 * \param[in] le
 */
void smApduAdaptLe(apdu_t *pApdu, U16 le)
{
    AddLe(pApdu, le);
}

/**
 * In the final stage before sending the APDU cmd one needs to update the values of lc and le.
 * \param[in,out] pApdu        APDU buffer
 * \param[in] lc
 * \param[in] le
 */
void smApduAdaptLcLe(apdu_t *pApdu, U16 lc, U16 le)
{
    SetLc(pApdu, lc);
    AddLe(pApdu, le);
}

/**
 * Reserves bytes for the LC in the command APDU and updated the pApdu data structure to match.
 * Must be called once in case the APDU cmd has a command data section.
 * \pre pApdu->hasData has been set.
 * \param[in,out] pApdu        APDU buffer
 */
static void ReserveLc(apdu_t * pApdu)
{
    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->lcLength = 0;

    ENSURE_OR_GO_EXIT(pApdu->hasData != 0);

    if (pApdu->extendedLength) {
        pApdu->lcLength = 3;
    }
    else {
        pApdu->lcLength = 1;
    }

    pApdu->offset += pApdu->lcLength;
    pApdu->buflen += pApdu->lcLength;
exit:
    return;
}

/**
 * Sets the LC value in the command APDU.
 * @pre ReserveLc(...) has been called or there is no command data section
 * @param[in,out] pApdu APDU buffer
 * @param[in]     lc    LC value to be set
 */
static void SetLc(apdu_t * pApdu, U16 lc)
{
    ENSURE_OR_GO_EXIT(pApdu != NULL);
    ENSURE_OR_GO_EXIT((pApdu->lcLength != 0) || (pApdu->hasData == 0));

    // NOTE:
    // pApdu->lcLength was set to its proper value in a call to ReserveLc(...)

    if (pApdu->hasData) {
        if (pApdu->extendedLength) {
            pApdu->lc = lc;
            // pApdu->lcLength = 3;
            pApdu->pBuf[APDU_OFFSET_LC] = 0x00;
            pApdu->pBuf[APDU_OFFSET_LC + 1] = (U8)(lc >> 8);
            pApdu->pBuf[APDU_OFFSET_LC + 2] = (U8)(lc & 0xFF);
        }
        else {
            pApdu->lc = lc;
            // pApdu->lcLength = 1;
            pApdu->pBuf[APDU_OFFSET_LC] = (U8)(lc & 0xFF);
        }
    }
    else {
        pApdu->lcLength = 0;
    }
exit:
    return;
}

/**
 * Adds the LE value to the command APDU.
 * @param pApdu              [IN/OUT] APDU buffer
 * @param le                 [IN] LE
 * @return
 */
static void AddLe(apdu_t * pApdu, U16 le)
{
    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->hasLe = true;
    pApdu->le = le;

    if (pApdu->extendedLength) {
        if (pApdu->hasData) {
            pApdu->pBuf[pApdu->offset] = (U8)(le >> 8);
            pApdu->pBuf[pApdu->offset + 1] = (U8)(le & 0xFF);
            pApdu->leLength = 2;
        }
        else {
            pApdu->pBuf[pApdu->offset] = 0x00;
            pApdu->pBuf[pApdu->offset + 1] = (U8)(le >> 8);
            pApdu->pBuf[pApdu->offset + 2] = (U8)(le & 0xFF);
            pApdu->leLength = 3;
        }
    }
    else {
        // regular length
        pApdu->pBuf[pApdu->offset] = (U8)(le & 0xFF);
        pApdu->leLength = 1;
    }

    pApdu->offset += pApdu->leLength;
    pApdu->buflen += pApdu->leLength;
exit:
    return;
}


#if 0
/**
 * @function             AddTlvItem
 * @description          Adds a Tag-Length-Value structure to the command APDU.
 * @param pApdu          [IN/OUT] APDU buffer.
 * @param tag            [IN] tag; either a 1-byte tag or a 2-byte tag
 * @param dataLength     [IN] length of the Value
 * @param pValue         [IN] Value
 * @return               SW_OK or ERR_BUF_TOO_SMALL
 */
U16 AddTlvItem(apdu_t * pApdu, U16 tag, U16 dataLength, const U8 *pValue)
{
    U8 msbTag = tag >> 8;
    U8 lsbTag = tag & 0xff;

    // If this is the first tag added to the buffer, we needs to ensure
    // the correct offset is used writing the data. This depends on
    // whether the APDU is a standard or an extended APDU.
    if (pApdu->hasData == 0)
    {
        pApdu->hasData = 1;
        ReserveLc(pApdu);
    }

    // Ensure no buffer overflow will occur before writing any data to buffer
    {
        U32 xtraData = 0;
        U32 u32_Offset = (U32)(pApdu->offset);

        xtraData = 1;
        // Tag
        if (msbTag != 0x00)
        {
            // 2-byte tag
            xtraData++;
        }

        // Length
        if (dataLength <= 0x7f)
        {
            // 1-byte length
            xtraData++;
        }
        else if (dataLength <= 0xff)
        {
            // 2-byte length
            xtraData += 2;
        }
        else
        {
            // 3-byte length
            xtraData += 3;
        }
        xtraData += dataLength;

        // Can we still add 'xtraData' to internal buffer without buffer overwrite?
        if ( (u32_Offset + xtraData) > MAX_APDU_BUF_LENGTH)
        {
            // Bufferflow would occur
            return ERR_BUF_TOO_SMALL;
        }
    }

    // Tag
    if (msbTag != 0x00)
    {
        // 2-byte tag
        pApdu->pBuf[pApdu->offset++] = msbTag;
    }
    pApdu->pBuf[pApdu->offset++] = lsbTag;

    // Length
    if (dataLength <= 0x7f)
    {
        // 1-byte length
        pApdu->pBuf[pApdu->offset++] = (U8) dataLength;
        pApdu->lc += 2 + dataLength;
    }
    else if (dataLength <= 0xff)
    {
        // 2-byte length
        pApdu->pBuf[pApdu->offset++] = 0x81;
        pApdu->pBuf[pApdu->offset++] = (U8) dataLength;
        pApdu->lc += 3 + dataLength;
    }
    else
    {
        // 3-byte length
        pApdu->pBuf[pApdu->offset++] = 0x82;
        pApdu->pBuf[pApdu->offset++] = dataLength >> 8;
        pApdu->pBuf[pApdu->offset++] = dataLength & 0xff;
        pApdu->lc += 4 + dataLength;
    }

    // Value
    memcpy(&pApdu->pBuf[pApdu->offset], pValue, dataLength);
    pApdu->offset += dataLength;

    // adapt length
    pApdu->buflen = pApdu->offset;

    return SW_OK;
}

/**
 * AddStdCmdData
 * \deprecated Use ::smApduAppendCmdData instead
 */
U16 AddStdCmdData(apdu_t * pApdu, U16 dataLen, const U8 *data)
{

    pApdu->hasData = 1;
    ReserveLc(pApdu);

    pApdu->lc += dataLen;

    // Value
    memcpy(&pApdu->pBuf[pApdu->offset], data, dataLen);
    pApdu->offset += dataLen;

    // adapt length
    pApdu->buflen = pApdu->offset;

    return pApdu->offset;
}

/**
 * @function                 ParseResponse
 * @description              Parses a received Tag-Length-Value structure (response APDU).
 * @param pApdu              [IN] APDU buffer
 * @param expectedTag        [IN] expected tag; either a 1-byte tag or a 2-byte tag
 * @param pLen               [IN,OUT] IN: size of buffer provided; OUT: length of the received Value
 * @param pValue             [OUT] received Value
 * @return status
 */
U16 ParseResponse(apdu_t *pApdu, U16 expectedTag, U16 *pLen, U8 *pValue)
{
    U16 tag = 0;
    U16 rv = ERR_GENERAL_ERROR;
    int foundTag = 0;
    U16 bufferLen = *pLen;

    *pLen = 0;

    if (pApdu->rxlen < 2) /* minimum: 2 byte for response */
    {
        return ERR_GENERAL_ERROR;
    }
    else
    {
        /* check status returned is okay */
        if ((pApdu->pBuf[pApdu->rxlen - 2] != 0x90) || (pApdu->pBuf[pApdu->rxlen - 1] != 0x00))
        {
            return ERR_GENERAL_ERROR;
        }
        else // response okay
        {
            pApdu->offset = 0;

            do
            {
                U16 len = 0;

                // Ensure we don't parse beyond the APDU Response Data
                if (pApdu->offset >= (pApdu->rxlen -2)) { break; }

                /* get the tag (see ISO 7816-4 annex D); limited to max 2 bytes */
                if ((pApdu->pBuf[pApdu->offset] & 0x1F) != 0x1F) /* 1 byte tag only */
                {
                    tag = (pApdu->pBuf[pApdu->offset] & 0x00FF);
                    pApdu->offset += 1;
                }
                else /* tag consists out of 2 bytes */
                {
                    tag = (pApdu->pBuf[pApdu->offset] << 8) + pApdu->pBuf[pApdu->offset + 1];
                    pApdu->offset += 2;
                }

                // Ensure we don't parse beyond the APDU Response Data
                if (pApdu->offset >= (pApdu->rxlen -2)) { break; }

                // tag is OK
                /* get the length (see ISO 7816-4 annex D) */
                if ((pApdu->pBuf[pApdu->offset] & 0x80) != 0x80)
                {
                    /* 1 byte length */
                    len = (pApdu->pBuf[pApdu->offset++] & 0x00FF);
                }
                else
                {
                    /* length consists of 2 or 3 bytes */

                    U8 additionalBytesForLength = (pApdu->pBuf[pApdu->offset++] & 0x7F);

                    if (additionalBytesForLength == 1)
                    {
                        len = pApdu->pBuf[pApdu->offset];
                        pApdu->offset += 1;
                    }
                    else if (additionalBytesForLength == 2)
                    {
                        len = (pApdu->pBuf[pApdu->offset] << 8) + pApdu->pBuf[pApdu->offset + 1];
                        pApdu->offset += 2;
                    }
                    else
                    {
                        return ERR_GENERAL_ERROR;
                    }
                }

                // Ensure we don't parse beyond the APDU Response Data
                if (pApdu->offset >= (pApdu->rxlen -2)) { break; }

                if (tag == expectedTag)
                {
                    // copy the value
                    if ( (len > 0) && (bufferLen >= len) )
                    {
                        *pLen = len;
                        memcpy(pValue, &pApdu->pBuf[pApdu->offset], *pLen);
                        rv = SW_OK;
                        foundTag = 1;
                        break;
                    }
                    else
                    {
                        rv = ERR_BUF_TOO_SMALL;
                        break;
                    }
                }

                // update the offset
                pApdu->offset += len;
            } while (!foundTag);
        }
    }

    return rv;
}

#endif // TGT_A71CH

/**
 * Add or append data to the body of a command APDU.
 * WARNING:
 * - Bufferoverflow fix not applied for SSS_HAVE_A71CH_SIM
 * WARNING for non-TGT_A71CH cases :
 * - TGT_A71CL: This function must only be called once in case pApdu->txHasChkSum is set
 */
U16 smApduAppendCmdData(apdu_t *pApdu, const U8 *data, U16 dataLen)
{
    U16 rv = ERR_GENERAL_ERROR;
    ENSURE_OR_GO_EXIT(pApdu != NULL);
    ENSURE_OR_GO_EXIT(data != NULL);
#ifdef TGT_A71CH
    // The maximum amount of data payload depends on (whichever is smaller)
    //   - STD-APDU (MAX=255 byte) / EXTENDED-APDU (MAX=65536 byte)
    //   - size of pApdu->pBuf (MAX_APDU_BUF_LENGTH)
    // Standard Length APDU's:
    //   There is a pre-processor macro in place that ensures 'pApdu->pBuf' is of sufficient size
    // Extended Length APDU's (not used by A71CH):
    //   APDU payload restricted by buffersize of 'pApdu->pBuf'
    U16 maxPayload_noLe;

    if (pApdu->extendedLength) {
        maxPayload_noLe = MAX_APDU_BUF_LENGTH - EXT_CASE4_APDU_OVERHEAD;
    }
    else {
        maxPayload_noLe = APDU_HEADER_LENGTH + APDU_STD_MAX_DATA;
    }
#endif // TGT_A71CH

#ifdef TGT_A71CL
    U16 maxPayload_noLe;

    maxPayload_noLe = MAX_APDU_BUF_LENGTH - EXT_CASE4_APDU_OVERHEAD;
    if (pApdu->txHasChkSum == 1) {
        maxPayload_noLe -= pApdu->txChkSumLength;
    }
#endif // TGT_A71CL

    // If this is the first commmand data section added to the buffer, we needs to ensure
    // the correct offset is used writing the data. This depends on
    // whether the APDU is a standard or an extended APDU.
    if (pApdu->hasData == 0)
    {
        pApdu->hasData = 1;
        ReserveLc(pApdu);
    }

#if SSS_HAVE_A71CH_SIM
    if (gEnableEnc)
    {
        pApdu->lc += (dataLen + sizeof(session_Tlv));
        //add SessionId_Tlv
        memcpy(&pApdu->pBuf[pApdu->offset], session_Tlv, sizeof(session_Tlv));
        pApdu->offset += sizeof(session_Tlv);
    }
    else
#endif // SSS_HAVE_A71CH_SIM
    {
        pApdu->lc += dataLen;
    }

#ifdef TGT_A71CL
    /* add for cl */
    if (pApdu->txHasChkSum == 1) {
        pApdu->lc += pApdu->txChkSumLength;
        pApdu->pBuf[pApdu->offset - 1] = (U8)pApdu->lc;
    }
#endif // TGT_A71CL

    // Value
#if defined(TGT_A71CH) || defined(TGT_A71CL)
    if (dataLen <= (maxPayload_noLe - pApdu->offset))
    {
        memcpy(&pApdu->pBuf[pApdu->offset], data, dataLen);
        pApdu->offset += dataLen;
    }
    else
    {
        return ERR_INTERNAL_BUF_TOO_SMALL;
    }
#else // defined(TGT_A71CH) || defined(TGT_A71CL)
    memcpy(&pApdu->pBuf[pApdu->offset], data, dataLen);
    pApdu->offset += dataLen;
#endif // defined(TGT_A71CH) || defined(TGT_A71CL)

    // adapt length
    pApdu->buflen = pApdu->offset;

    rv = pApdu->offset;
exit:
    return rv;
}

/**
 * Gets the Status Word from the APDU.
 * @param[in]      pApdu Pointer to the APDU.
 * @param[in,out]  pIsOk IN: Pointer to the error indicator, allowed to be NULL; OUT: Points to '1' in case SW is 0x9000
 * @return      Status Word or ::ERR_COMM_ERROR
 */
U16 smGetSw(apdu_t *pApdu, U8 *pIsOk)
{
    U16 sw = ERR_API_ERROR;
    U16 offset;
    ENSURE_OR_GO_EXIT(pApdu != NULL);
    ENSURE_OR_GO_EXIT(pIsOk != NULL);

    if (pApdu->rxlen >= 2)
    {
        offset = pApdu->rxlen - 2;
        sw = (pApdu->pBuf[offset] << 8) + pApdu->pBuf[offset + 1];

        if (sw == SW_OK)
        {
            *pIsOk = 1;
        }
        else
        {
            *pIsOk = 0;
        }
    }
    else
    {
        sw = ERR_COMM_ERROR;
        *pIsOk = 0;

    }
exit:
    return sw;
}

/**
 * verify crc checksum.
 * \param[in] pApdu      APDU buffer
 * \param[in] dataLen    data length to be use for crc caluate
 * \return               offset in APDU buffer after the header
 */
#if defined(TGT_A71CL)
static U8 smVerifyCrc(apdu_t *pApdu, U16 dataLen)
{
    U16 crc = 0;
    U16 recvCrc = 0;

    ENSURE_OR_GO_EXIT(pApdu != NULL);
    //FIXME: Where is the definition for below function?
    //crc = CL_CalCRC(&pApdu->pBuf[pApdu->offset], (U32)dataLen, 0xFFFF);
    recvCrc = *(U16*)&pApdu->pBuf[pApdu->offset + dataLen];
    if (crc != recvCrc) {
        return 0;
    } else {
        return 1;
    }
exit:
    return 0;
}
#endif
/**
 * Retrieve the response data of the APDU response, in case the status word matches ::SW_OK
 */
U16 smApduGetResponseBody(apdu_t *pApdu, U8 *buf, U16 *bufLen)
{
    U16 tailInfoLen = 2;
    U16 rv = ERR_GENERAL_ERROR;

    ENSURE_OR_GO_EXIT(pApdu != NULL);
    if (pApdu->rxlen < 2) /* minimum: 2 byte for response */
    {
        *bufLen = 0;
        return ERR_GENERAL_ERROR;
    }
    else
    {
        /* check status returned is okay */
        if (((pApdu->pBuf[pApdu->rxlen - 2] != 0x90) || (pApdu->pBuf[pApdu->rxlen - 1] != 0x00)) &&
            (pApdu->pBuf[pApdu->rxlen -2] != 0x63) &&
            (pApdu->pBuf[pApdu->rxlen - 2] != 0x95)) {
            *bufLen = 0;
            return ERR_GENERAL_ERROR;
        }
        else // response okay
        {
            pApdu->offset = 0;
#if defined(TGT_A71CL)
            if (pApdu->rxHasChkSum == 1) {
                tailInfoLen += pApdu->rxChkSumLength;
            }
#endif
            if ((pApdu->rxlen - tailInfoLen) > *bufLen)
            {
                *bufLen = 0;
                return ERR_BUF_TOO_SMALL;
            }
            else
            {
                *bufLen = pApdu->rxlen - tailInfoLen;
#if defined(TGT_A71CL)
                if (pApdu->rxHasChkSum == 1) {
                    if (smVerifyCrc(pApdu, *bufLen)) {
                        memcpy(buf, &(pApdu->pBuf[pApdu->offset]), *bufLen);
                    } else {
                        return ERR_CRC_CHKSUM_VERIFY;
                    }
                }
                else
#endif
                {
                    if (*bufLen) {
                        memcpy(buf, &(pApdu->pBuf[pApdu->offset]), *bufLen);
                    }
                }
            }
        }
    }

    rv = SW_OK;
exit:
    return rv;
}

#ifdef TGT_A71CL

/**
 * In the final stage before sending the APDU cmd one needs to update checksum value.
 * \param[in,out] pApdu        APDU buffer
 * \param[in] chksum
 */
U16 smApduAdaptChkSum(apdu_t *pApdu, U16 chkSum)
{
    U16 rv = ERR_GENERAL_ERROR;
    // assert(pApdu->txHasChkSum == 1);
    // U16 tmpchkSum = (chkSum >> 8)|(chkSum << 8);

    ENSURE_OR_GO_EXIT(pApdu != NULL);
    if (pApdu->txHasChkSum) {
        memcpy(&pApdu->pBuf[pApdu->offset], &chkSum, pApdu->txChkSumLength);
    }
    pApdu->buflen += pApdu->txChkSumLength;
    pApdu->offset += pApdu->txChkSumLength;

    rv = pApdu->offset;
exit:
    return rv;
}
#endif

bool smApduGetArrayBytes(char *str, size_t *len, uint8_t *buffer, size_t buffer_len)
{
    if ((strlen(str) % 2) != 0) {
        LOG_E("Invalid length");
        return false;
    }

    *len = strlen(str) / 2;
    if (buffer_len < *len)
    {
        LOG_E("Insufficient buffer size\n");
        *len = 0;
        return false;
    }
    char *pos = str;
    for (size_t count = 0; count < *len; count++) {
        if (sscanf(pos, "%2hhx", &buffer[count]) < 1) {
            *len = 0;
            return false;
        }
        pos += 2;
    }
    return true;
}

bool smApduGetTxRxCase(uint8_t *apdu, size_t apduLen, size_t* data_offset, size_t *dataLen, apduTxRx_case_t *apdu_case)
{
    *data_offset = 0;
    *dataLen = 0;
    *apdu_case = APDU_TXRX_CASE_INVALID;
    //Invalid apdu
    if (apduLen < 4)
    {
        LOG_E("Wrong APDU format\n");
        return false;
    }

    //Case 1
    if (apduLen == 4)
    {
        *apdu_case = APDU_TXRX_CASE_1;
        return true;
    }
    //Case 2S
    else if (apduLen == 5)
    {
        *apdu_case = APDU_TXRX_CASE_2;
        return true;
    }
    else
    {
        size_t byte5 = apdu[4] & 0xFF;
        if (byte5 != 0x0)
        {
            if (apduLen == 5 + byte5)
            {
                //case 3S
                *apdu_case = APDU_TXRX_CASE_3;
                *data_offset = 5;
                *dataLen = byte5;
            }
            else if (apduLen == 6 + byte5)
            {
                //case 4S
                *apdu_case = APDU_TXRX_CASE_4;
                *data_offset = 5;
                *dataLen = byte5;
            }
            else
            {
                LOG_E("Wrong APDU format\n");
                return false;
            }
        }
        else if (apduLen == 7)
        {
            //case 2E
            *apdu_case = APDU_TXRX_CASE_2E;
        }
        else if (apduLen < 7)
        {
            LOG_E("Wrong APDU format\n");
            return false;
        }
        else
        {
            size_t len = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
            if (apduLen == 7 + len) {
                //case 3E
                *apdu_case = APDU_TXRX_CASE_3E;
                *data_offset = 7;
                *dataLen = len;
            }
            else if (apduLen == 9 + len) {
                //Case 4E
                *apdu_case = APDU_TXRX_CASE_4E;
                *data_offset = 7;
                *dataLen = len;
            }
            else
            {
                LOG_E("Wrong APDU format\n");
                return false;
            }
        }
    }
    return true;
}
