/*
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * This file defines the API of the APDU parser for AX host library.
 * @par History
 * 1.0   31-mar-2014 : Initial version
 *
 */

#ifndef _SM_APDU_H_
#define _SM_APDU_H_

#include "apduComm.h"
#include "sm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef A71_IGNORE_PARAM_CHECK
#error "Do not remove API parameter check"
#endif

/* ------------------------------ */


#define MAX_APDU_BUF_LENGTH             (256 + 1024)  // This value has not been optimized for TGT_A71CH (256+64)
#define MAX_EXT_APDU_BUF_LENGTH         (32769) // extended APDU Max supported Len is 0x7FFF + 2 bytes status code


#define APDU_HEADER_LENGTH                (5)
#define APDU_EXTENDED_HEADER_LENGTH       (7)
#define EXT_CASE4_APDU_OVERHEAD           (9)
#define SCP03_OVERHEAD                   (24)   // padding (=16) + mac (=8)
#define RSP_APDU_STATUS_OVERHEAD          (2)
#define APDU_STD_MAX_DATA               (255)

// <Should be in a TLV specific header file>
#ifdef TGT_A70CI
#define TAG_SST_IDENTIFIER             (0x01)
#define TAG_SST_INDEX                  (0x02)
#define TAG_ECC_PRIVATE_KEY            (0x03)
#define TAG_ECC_PUBLIC_KEY             (0x04)
#define TAG_SHARED_SECRET              (0x05)
#define TAG_RSA_PRIVATE_KEY_P          (0x06)
#define TAG_RSA_PRIVATE_KEY_Q          (0x07)
#define TAG_RSA_PRIVATE_KEY_DP         (0x08)
#define TAG_RSA_PRIVATE_KEY_DQ         (0x09)
#define TAG_RSA_PRIVATE_KEY_IPQ        (0x0A)
#define TAG_PUBLIC_KEY                 (0x0B)
#define TAG_AES_KEY                    (0x0C)
#define TAG_AUTH_PUBLIC_KEY_ID         (0x0D)
#define TAG_CONTEXT                    (0x0F)
#define TAG_DIRECTION                  (0x10)
#define TAG_IV                         (0x11)
#define TAG_INPUT_DATA                 (0x12)
#define TAG_OUTPUT_DATA                (0x13)
#define TAG_AUTHENTICATION_DATA        (0x14)
#define TAG_GMAC_DATA                  (0x15)
#define TAG_GMAC_LENGTH                (0x16)
#define TAG_KEYWRAP_ALGO               (0x17)
#define TAG_HASH                       (0x18)
#define TAG_SIGNATURE                  (0x19)
#define TAG_VERIFICATION               (0x1A)
#define TAG_CERTIFICATE                (0x1B)
#define TAG_SIZE                       (0x1C)
#define TAG_SALT                       (0x1E)
#elif defined(TGT_A70CM)
#define TAG_DLMS_SECURITY_BYTE         (0x00)
#define TAG_SST_IDENTIFIER             (0x01)
#define TAG_SST_INDEX                  (0x02)
#define TAG_ECC_PRIVATE_KEY            (0x03)
#define TAG_ECC_PUBLIC_KEY             (0x04)
#define TAG_SHARED_SECRET              (0x05)
#define TAG_RSA_PRIVATE_KEY_P          (0x06)
#define TAG_RSA_PRIVATE_KEY_Q          (0x07)
#define TAG_RSA_PRIVATE_KEY_DP         (0x08)
#define TAG_RSA_PRIVATE_KEY_DQ         (0x09)
#define TAG_RSA_PRIVATE_KEY_IPQ        (0x0A)
#define TAG_RSA_PUBLIC_KEY_MOD         (0x0B)
#define TAG_AES_KEY                    (0x0C)
#define TAG_WRAPPED_AES_KEY            (0x0D)
#define TAG_CONTEXT                    (0x0E)
#define TAG_DIRECTION                  (0x0F)
#define TAG_IV                         (0x10)
#define TAG_INPUT_DATA                 (0x11)
#define TAG_OUTPUT_DATA                (0x12)
#define TAG_AUTHENTICATION_DATA        (0x13)
#define TAG_GMAC_DATA                  (0x14)
#define TAG_GMAC_LENGTH                (0x15)
#define TAG_KEYWRAP_ALGO               (0x16)
#define TAG_HASH                       (0x17)
#define TAG_SIGNATURE                  (0x18)
#define TAG_DLMS_AK_INDEX              (0x19)
#define TAG_VERIFICATION               (0x1A)
#define TAG_CERTIFICATE                (0x1B)
#define TAG_OFFSET                     (0x1C)
#define TAG_SIZE                       (0x1D)
#define TAG_SST_WRAPPING_KEY_INDEX     (0x1E)
#else //
/// @cond not_relevant_for_A71ch & A71cl
#define TAG_DLMS_SECURITY_BYTE         (0x00)
#define TAG_SST_IDENTIFIER             (0x01)
#define TAG_SST_INDEX                  (0x02)
#define TAG_ECC_PRIVATE_KEY            (0x03)
#define TAG_ECC_PUBLIC_KEY             (0x04)
#define TAG_SHARED_SECRET              (0x05)
#define TAG_RSA_PRIVATE_KEY_P          (0x06)
#define TAG_RSA_PRIVATE_KEY_Q          (0x07)
#define TAG_RSA_PRIVATE_KEY_DP         (0x08)
#define TAG_RSA_PRIVATE_KEY_DQ         (0x09)
#define TAG_SST_IDENTIFIER2            (0x0A)
#define TAG_SST_INDEX2                 (0x0B)
#define TAG_AES_KEY                    (0x0C)
#define TAG_WRAPPED_AES_KEY            (0x0D)
#define TAG_CONTEXT                    (0x0E)
#define TAG_DIRECTION                  (0x0F)
#define TAG_IV                         (0x10)
#define TAG_INPUT_DATA                 (0x11)
#define TAG_OUTPUT_DATA                (0x12)
#define TAG_AUTHENTICATION_DATA        (0x13)
#define TAG_GMAC_DATA                  (0x14)
#define TAG_GMAC_LENGTH                (0x15)
#define TAG_KEYWRAP_ALGO               (0x16)
#define TAG_HASH                       (0x17)
#define TAG_SIGNATURE                  (0x18)
#define TAG_STATE                      (0x19)
#define TAG_VERIFICATION               (0x1A)
#define TAG_CERTIFICATE                (0x1B)
#define TAG_OFFSET                     (0x1C)
#define TAG_SIZE                       (0x1D)
#define TAG_SST_WRAPPING_KEY_INDEX     (0x1E)
#define TAG_INTERFACE                  (0x1F)
#define TAG_CHUNK_NUMBER               (0x23)
#define TAG_SCP_MIN_SEC_LEVEL          (0x24)
#define TAG_STATUS_WORD                (0x25)
/// @endcond
#endif // TGT_A70CI
// </Should be in a TLV specific header file>

/* ------------------------------ */
#define AX_CLA                       (0x80)

// #define SW_WARNING_FILE_DEACTIVATED         (0x6283)
// #define SW_WARNING_FILE_TERMINATED          (0x6285)

#define SW_WRONG_LENGTH                     (0x6700) //!< ISO7816-4 defined status word: Wrong Length of data
#define SW_SECURE_MESSAGING_NOT_SUPPORTED   (0x6882) //!< ISO7816-4 defined status word
#define SW_SECURITY_STATUS_NOT_SATISFIED    (0x6982) //!< ISO7816-4 defined status word
#define SW_DATA_INVALID                     (0x6984) //!< ISO7816-4 defined status word
#define SW_CONDITIONS_NOT_SATISFIED         (0x6985) //!< ISO7816-4 defined status word: Conditions of use not satisfied, e.g. a command is not allowed, the provided identifier is not applicable or the index is out of range.
#define SW_COMMAND_NOT_ALLOWED              (0x6986) //!< ISO7816-4 defined status word
#define SW_WRONG_DATA                       (0x6A80) //!< ISO7816-4 defined status word: Wrong data, e.g. the command does not have the right parameters or a parameter is not correct (size, structure).
#define SW_FILE_NOT_FOUND                   (0x6A82) //!< ISO7816-4 defined status word
#define SW_INCORRECT_P1P2                   (0x6A86) //!< ISO7816-4 defined status word: Incorrect P1-P2 parameters
#define SW_INS_NOT_SUPPORTED                (0x6D00) //!< ISO7816-4 defined status word: INS byte not supported
#define SW_CLA_NOT_SUPPORTED                (0x6E00) //!< ISO7816-4 defined status word: CLA byte not supported
#define SW_NO_ERROR                         (0x9000) //!< ISO7816-4 defined status word

#define USE_STANDARD_APDU_LEN 0 //!< Create a standard length APDU.
#define USE_EXTENDED_APDU_LEN 1 //!< Create an extended length APDU.
#define SESSION_ID_LEN 4

U8 SetApduHeader(apdu_t * pApdu, U8 extendedLength);
U8 AllocateAPDUBuffer(apdu_t * pApdu);
U8 FreeAPDUBuffer(apdu_t * pApdu);
void smApduAdaptLcLe(apdu_t *pApdu, U16 lc, U16 le);
void smApduAdaptLc(apdu_t *pApdu, U16 lc);
void smApduAdaptLe(apdu_t *pApdu, U16 le);
// U16 GetStatusWord(apdu_t *pApdu);
U16 smGetSw(apdu_t *pApdu, U8 *pIsOk);
void set_SessionId_Tlv(U32 sessionId);


U16 AddTlvItem(apdu_t * pApdu, U16 tag, U16 dataLength, const U8 *pValue);
U16 ParseResponse(apdu_t * pApdu, U16 expectedTag, U16 * pLen, U8* pValue);
U16 AddStdCmdData(apdu_t * pApdu, U16 dataLen, const U8 *data);

U16 smApduGetResponseBody(apdu_t *pApdu, U8 *buf, U16 *bufLen);
U16 smApduAppendCmdData(apdu_t * pApdu, const U8 *data, U16 dataLen);
U16 smApduAdaptChkSum(apdu_t *pApdu, U16 chkSum);

/**
 * @brief Check and convert given hex string to array of bytes to buffer.
 *
 * Memory allocation needs to be done by the caller, boundary checks on the output
 * are performed, null-termination is always added.
 * @param[in] str: The binary data to convert.
 * @param[in] buffer: buffer to which converted array to be copied.
 * @param[in] buffer_len: Size of the available buffer for sanity check.
 * @param[out] len: The length of the binary data written to buffer.
 * @return True if conversion is successful.
 */
bool smApduGetArrayBytes(char *str, size_t *len, uint8_t * buffer, size_t buffer_len);

/**
    * @brief Parse given apdu command and return command data offset and command data length along with case-id as described in ISO/IEC FDIS 7816-3 spec.
    *
    * @param[in] apdu: Buffer containing APDU command.
    * @param[in] apduLen: The length of APDU command.
    * @param[out] data_offset: Offset of data field if present.
    * @param[out] dataLen: Length of data field (LC field value)  if present.
    * @param[out] apdu_case: APDU txrx case accoring to 7816 spec.
    * @return True if APDU command has valid format.
    */
bool smApduGetTxRxCase(uint8_t *apdu, size_t apduLen, size_t* data_offset, size_t *dataLen, apduTxRx_case_t *apdu_case);


#ifdef __cplusplus
}
#endif
#endif //_SM_APDU_H_
