/*
* Copyright 2018 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NXSCP03_CONST_H_
#define NXSCP03_CONST_H_
/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#define SCP_GP_IU_KEY_DIV_DATA_LEN 10   //!< SCP GP Init Update key Div length
#define SCP_GP_IU_KEY_INFO_LEN 3        //!< SCP GP Init Update key info length
#define SCP_GP_CARD_CHALLENGE_LEN 8     //!< SCP GP Card Challenge length
#define SCP_GP_HOST_CHALLENGE_LEN 8     //!< SCP GP Host Challenge length
#define SCP_GP_IU_CARD_CRYPTOGRAM_LEN 8 //!< SCP GP Card Cryptogram length
#define SCP_GP_IU_SEQ_COUNTER_LEN 3     //!< SCP GP Init Update Sequence Counter length
#define SCP_GP_SW_LEN 2                 //!< SCP Status Word length
#define CRYPTO_KEY_CHECK_LEN (3)        //!< SCP key check length

#define ASN_ECC_NIST_256_HEADER_LEN 26
#define KEY_PARAMETER_REFERENCE_TAG 0xF0
#define KEY_PARAMETER_REFERENCE_VALUE_LEN 0x01 // Fixed for Nist256key
#define KEY_PARAMETER_REFERENCE_VALUE 0x03 // key parameter value need to check in the spec it is 00
#define GPCS_KEY_TYPE_ECC_NIST256 0xB0
#define GPCS_KEY_TYPE_AES 0x88
#define GPCS_KEY_LEN_AES 16

#define SCP_ID 0xAB
#define SCP_CONFIG 0x01

#define SCP_MCV_LEN 16 // MAC Chaining Length

#define CLA_ISO7816 (0x00)         //!< ISO7816-4 defined CLA byte
#define CLA_GP_7816 (0x80)         //!< GP 7816-4 defined CLA byte
#define CLA_GP_SECURITY_BIT (0x04) //!< GP CLA Security bit

#define INS_GP_INITIALIZE_UPDATE (0x50)     //!< Global platform defined instruction
#define INS_GP_EXTERNAL_AUTHENTICATE (0x82) //!< Global platform defined instruction
#define INS_GP_SELECT (0xA4)                //!< Global platform defined instruction
#define INS_GP_PUT_KEY (0xD8)               //!< Global platform defined instruction
#define INS_GP_INTERNAL_AUTHENTICATE  (0x88)   //!< Global platform defined instruction
#define INS_GP_GET_DATA  (0xCA)                //!< Global platform defined instruction
#define P1_GP_GET_DATA (0xBF)               //!< Global platform defined instruction
#define P2_GP_GET_DATA (0x21)               //!< Global platform defined instruction

/* Sizes used in SCP */
#define AES_KEY_LEN_nBYTE (16) //!< AES key length

#define SCP_KEY_SIZE (16)
#define SCP_CMAC_SIZE (16)       // length of the CMAC calculated (and used as MAC chaining value)
#define SCP_IV_SIZE (16)         // length of the Inital Vector
#define SCP_COMMAND_MAC_SIZE (8) // length of the MAC appended in the APDU payload (8 'MSB's)

#define DATA_CARD_CRYPTOGRAM (0x00)       //!< Data card cryptogram
#define DATA_HOST_CRYPTOGRAM (0x01)       //!< Data host cryptogram
#define DATA_DERIVATION_SENC (0x04)       //!< Data Derivation to generate Sess ENC Key
#define DATA_DERIVATION_SMAC (0x06)       //!< Data Derivation to generate Sess MAC Key
#define DATA_DERIVATION_SRMAC (0x07)      //!< Data Derivation to generate Sess RMAC Key
#define DATA_DERIVATION_INITIAL_MCV (0x08)//!< Data Derivation to generate Initial MCV
#define DATA_DERIVATION_L_64BIT (0x0040)  //!< Data Derivation length
#define DATA_DERIVATION_L_128BIT (0x0080) //!< Data Derivation length
#define DATA_DERIVATION_KDF_CTR (0x01)    //!< Data Derivation counter

#define DD_LABEL_LEN 12 //!< Data Derivation length

/* defines used to indicate the command type */
#define C_MAC (0x01) //!< C MAC security
#define C_ENC (0x02) //!< C ENC security
#define R_MAC (0x10) //!< R MAC security
#define R_ENC (0x20) //!< R ENC security

#define SECLVL_CDEC_RENC_CMAC_RMAC (0x33) //!< Full security

#define SCP_DATA_PAD_BYTE 0x80 //!< Data Pad Byte

#define CMAC_SIZE (8) //!< CMAC Compare size

#define SCP_OK (SW_OK)
#define SCP_UNDEFINED_CHANNEL_ID (0x7041)            //!< Undefined SCP channel identifier
#define SCP_FAIL (0x7042)                            //!< Undefined SCP channel identifier
#define SCP_CARD_CRYPTOGRAM_FAILS_TO_VERIFY (0x7043) //!< Undefined SCP channel identifier
#define SCP_PARAMETER_ERROR (0x7044)                 //!< Undefined SCP channel identifier

#define NO_C_MAC_NO_C_ENC_NO_R_MAC_NO_R_ENC  0                   //!< No security requested
#define C_MAC_NO_C_ENC_R_MAC_NO_R_ENC  (C_MAC | R_MAC)           //!< One apply MAC'ing (Not implemented)
#define C_MAC_C_ENC_R_MAC_R_ENC  (C_MAC | C_ENC | R_MAC | R_ENC) //!< Apply full security
#define SECURITY_LEVEL  C_MAC_C_ENC_R_MAC_R_ENC

#define  APPLET_SCP_INIT_UPDATE_LEN 0x0D    //!< Applet SCP Initialize Update Length
#define  APPLET_SCP_EXT_AUTH_LEN  0x15      //!< Applet SCP External Authenticate Length

#endif /*NXSCP03_CONST_H_*/
