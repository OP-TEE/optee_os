/*
* Copyright 2018 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NXSCP03_APIS_H_
#define NXSCP03_APIS_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#ifdef __cplusplus
extern "C"
#endif

#include "nxScp03_Types.h"
#include "nxScp03_Const.h"

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/**
* To Secure the on going communicatation
*/

/**
* To Verify SE
*/
sss_status_t nxScp03_HostLocal_VerifyCardCryptogram(
    sss_object_t *keyObj, uint8_t *hostChallenge, uint8_t *cardChallenge, uint8_t *cardCryptogram);

/**
* To Verify Host
*/
sss_status_t nxScp03_HostLocal_CalculateHostCryptogram(
    sss_object_t *keyObj, uint8_t *hostChallenge, uint8_t *cardChallenge, uint8_t *hostCryptogram);

/**
* To sending secure Command APDU
*/
sss_status_t nxSCP03_Encrypt_CommandAPDU(
    NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *cmdBuf, size_t *cmdBufLen);
/**
*  To provide additional Security with MAC as CRC
*/
sss_status_t nxpSCP03_CalculateMac_CommandAPDU(
    NXSCP03_DynCtx_t *pdySCP03SessCtx, uint8_t *pCmdBuf, size_t pCmdBufLen, uint8_t *mac, size_t *macLen);

/**
*   To get Plain Response APDU
*/
uint16_t nxpSCP03_Decrypt_ResponseAPDU(
    NXSCP03_DynCtx_t *pdySCP03SessCtx, size_t cmdBufLen, uint8_t *rspBuf, size_t *pRspBufLen, uint8_t hasle);

/*
*   To set the derivation data
*/
void nxScp03_setDerivationData(
    uint8_t ddA[], uint16_t *pDdALen, uint8_t ddConstant, uint16_t ddL, uint8_t iCounter, uint8_t *context, uint16_t contextLen);

/**
* To Generate Session Keys
*/
sss_status_t nxScp03_Generate_SessionKey(
    sss_object_t *keyObj, uint8_t *inData, uint32_t inDataLen, uint8_t *outSignature, uint32_t *outSignatureLen);

/**
* To Maintain count of commands
*/
void nxpSCP03_Inc_CommandCounter(NXSCP03_DynCtx_t *pdySCP03SessCtx);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* NXSCP03_APIS_H_ */
