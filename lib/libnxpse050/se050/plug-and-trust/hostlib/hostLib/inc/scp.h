/*
* Copyright 2016,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

/**
 * @par Description
 * This file defines the interface to an APDU transfer function supporting both
 * communication in the clear and channel encryption.
 * @par History
 *
 */

#ifndef SCP_H
#define SCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "smCom.h"

/// @cond
#define HOST_CHANNEL_STATE_IDX  0
#define ADMIN_CHANNEL_STATE_IDX 1

/* Sizes used in SCP */
#define AES_KEY_LEN_nBYTE               (16)
#define DES_KEY_LEN_nBYTE               (16)

#define SCP_CRYPTOGRAM_SIZE             (16)
#define SCP_CHALLENGE_SIZE              (8)
#define SCP_KEY_SIZE                    (16)
#define SCP_CMAC_SIZE                   (16) // length of the CMAC calculated (and used as MAC chaining value)
#define SCP_COMMAND_MAC_SIZE            (8)  // length of the MAC appended in the APDU payload (8 'MSB's)

/* defines used to indicate the command type */
#define C_MAC                           (0x01)
#define C_ENC                           (0x02)
#define R_MAC                           (0x10)
#define R_ENC                           (0x20)

#define SECLVL_CDEC_RENC_CMAC_RMAC      (0x33)

#define SCP02_SECLVL_CMAC               (0x01)
#define SCP02_SECLVL_CDEC_CMAC          (0x03)
#define SCP02_SECLVL_CDEC_CMAC_RMAC     (0x13)

#define SCP03_KEY_ID                    (0x01)

#define PUT_KEYS_MULTIPLE_KEYS          (0x80)
#define PUT_KEYS_KEY_TYPE_CODING_AES    (0x88)
#define PUT_KEYS_KEY_IDENTIFIER         ((PUT_KEYS_MULTIPLE_KEYS) | (SCP03_KEY_ID))

/* security levels, matching the CLA bytes for each level */
#define SECLVL_OFF                      (0x80)
#define SECLVL_MAC                      (0xC0)
#define SECLVL_ENC                      (0xE0)

#define DD_INPUT_SIZE                   (32)

#define DD_OFFSET_SESSION_COUNTER       (10)
#define DD_OFFSET_DD_CONSTANT           (11)
#define DD_OFFSET_L_MSB                 (13)
#define DD_OFFSET_L_LSB                 (14)
#define DD_OFFSET_I                     (15)
#define DD_OFFSET_HOST_CHALLENGE        (16)
#define DD_OFFSET_CARD_CHALLENGE        (24)

#define DATA_CARD_CRYPTOGRAM     (0x00)
#define DATA_HOST_CRYPTOGRAM     (0x01)
#define DATA_DERIVATION_SENC     (0x04)
#define DATA_DERIVATION_SMAC     (0x06)
#define DATA_DERIVATION_SRMAC    (0x07)
#define DATA_DERIVATION_L_64BIT  (0x0040)
#define DATA_DERIVATION_L_128BIT (0x0080)
#define DATA_DERIVATION_KDF_CTR  (0x01)

#define DD_LABEL_LEN 12

#define SCP_GP_IU_KEY_DIV_DATA_LEN   10
#define SCP_GP_IU_KEY_INFO_LEN        3
#define SCP02_GP_IU_KEY_INFO_LEN      2
#define SCP_GP_CARD_CHALLENGE_LEN     8
#define SCP02_GP_CARD_CHALLENGE_LEN   6
#define SCP_GP_HOST_CHALLENGE_LEN     8
#define SCP_GP_IU_CARD_CRYPTOGRAM_LEN 8
#define SCP_GP_IU_SEQ_COUNTER_LEN     3
#define SCP02_GP_IU_SEQ_COUNTER_LEN   2
#define SCP_GP_SW_LEN                 2
#define CRYPTO_KEY_CHECK_LEN         (3)

#define SCP_MCV_LEN 16 // MAC Chaining Length
/// @endcond

/**
 * Enumerated type encoding the security level requested to be applied to the APDU.
 */
typedef enum
{
    NO_C_MAC_NO_C_ENC_NO_R_MAC_NO_R_ENC = 0,                              //!< No security requested
    C_MAC_NO_C_ENC_R_MAC_NO_R_ENC       = (C_MAC | R_MAC),                //!< One apply MAC'ing (Not implemented)
    C_MAC_C_ENC_R_MAC_R_ENC             = (C_MAC | C_ENC | R_MAC | R_ENC) //!< Apply full security
} scp_CommandType_t;

/**
 * Exchanges APDU, applies SCP03 encryption depending on \p type parameter and on the
 * authentication status of the SCP03 channel.
 *
 * @param[in]     conn_ctx     connection context
 * @param[in,out] pApdu        apdu_t datastructure
 * @param[in]     type         encryption/mac request
 *
 * @retval ::SMCOM_OK                  Operation successful
 * @retval ::SMCOM_SND_FAILED          Send Failed
 * @retval ::SMCOM_RCV_FAILED          Receive Failed
 * @retval ::ERR_CRYPTO_ENGINE_FAILED  Failure in crypto engine
 * @retval ::SCP_RSP_MAC_FAIL          MAC on response failed to verify
 * @retval ::SCP_DECODE_FAIL           Encrypted Response did not decode to correctly padded plaintext
 */
U32 scp_Transceive(void *conn_ctx, apdu_t * pApdu, scp_CommandType_t type);

#ifdef __cplusplus
}
#endif
#endif /* _SCP_H_ */
