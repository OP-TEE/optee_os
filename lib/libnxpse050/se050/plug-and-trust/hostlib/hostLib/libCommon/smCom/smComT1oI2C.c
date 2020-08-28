/*
 * Copyright 2016-2018,2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * This file implements the SmCom T1oI2C communication layer.
 *
 *****************************************************************************/

#ifdef T1oI2C

#include <assert.h>

#include "smComT1oI2C.h"
#include "phNxpEse_Api.h"
#include "phNxpEseProto7816_3.h"

#include "i2c_a7.h"
#include "sm_printf.h"
#include "phEseStatus.h"
#include "sm_apdu.h"

#ifdef FLOW_VERBOSE
#define NX_LOG_ENABLE_SMCOM_DEBUG 1
#else
//#define NX_LOG_ENABLE_SMCOM_DEBUG 1
#endif

#include "nxLog_smCom.h"
#include "nxEnsure.h"

static U32 smComT1oI2C_Transceive(void* conn_ctx, apdu_t * pApdu);
static U32 smComT1oI2C_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen);
U16 smComT1oI2C_AnswerToReset(void* conn_ctx, U8 *T1oI2Catr, U16 *T1oI2CatrLen);

U16 smComT1oI2C_Close(void *conn_ctx, U8 mode)
{
    ESESTATUS status;
    status=phNxpEse_EndOfApdu(conn_ctx);
    //status=phNxpEse_chipReset();
    if(status ==ESESTATUS_SUCCESS)
    {
        status=phNxpEse_close(conn_ctx);
    }
    else
    {
        LOG_E("Failed to close session ");
        return SMCOM_COM_FAILED;
    }
    return SMCOM_OK;
}


U16 smComT1oI2C_Init(void **conn_ctx, const char *pConnString)
{
    ESESTATUS ret;
    phNxpEse_initParams initParams;
    initParams.initMode = ESE_MODE_NORMAL;

    if(conn_ctx != NULL) {
        *conn_ctx = NULL;
    }
    ret = phNxpEse_open(conn_ctx, initParams, pConnString);
    if (ret != ESESTATUS_SUCCESS)
    {
        LOG_E(" Failed to create physical connection with ESE ");
        return SMCOM_COM_FAILED;
    }
    return SMCOM_OK;
}

U16 smComT1oI2C_Open(void *conn_ctx, U8 mode, U8 seqCnt, U8 *T1oI2Catr, U16 *T1oI2CatrLen)
{
    ESESTATUS ret;
    phNxpEse_data AtrRsp;
    phNxpEse_initParams initParams;
    initParams.initMode = ESE_MODE_NORMAL;
    AtrRsp.len = *T1oI2CatrLen;
    AtrRsp.p_data = T1oI2Catr;

    if (conn_ctx == NULL) {
        smComT1oI2C_Init(NULL, NULL);
    }

    ret=phNxpEse_init(conn_ctx, initParams, &AtrRsp);
    if (ret != ESESTATUS_SUCCESS)
    {
        *T1oI2CatrLen=0;
        LOG_E(" Failed to Open session ");
        return SMCOM_COM_FAILED;
    }
    else
    {
       *T1oI2CatrLen = AtrRsp.len ; /*Retrive INF FIELD*/
    }
    smCom_Init(&smComT1oI2C_Transceive, &smComT1oI2C_TransceiveRaw);
    return SMCOM_OK;
}

static U32 smComT1oI2C_Transceive(void* conn_ctx, apdu_t * pApdu)
{
    U32 respLen= MAX_APDU_BUF_LENGTH;
    U32 retCode = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    retCode = smComT1oI2C_TransceiveRaw(conn_ctx, (U8 *)pApdu->pBuf, pApdu->buflen, pApdu->pBuf, &respLen);
    pApdu->rxlen = (U16)respLen;
exit:
    return retCode;
}

static U32 smComT1oI2C_TransceiveRaw(void* conn_ctx, U8 * pTx, U16 txLen, U8 * pRx, U32 * pRxLen)
{
    phNxpEse_data pCmdTrans;
    phNxpEse_data pRspTrans={0};
    ESESTATUS txnStatus;

    pCmdTrans.len = txLen;
    pCmdTrans.p_data = pTx;

    pRspTrans.len = *pRxLen;
    pRspTrans.p_data = pRx;

    LOG_MAU8_D("APDU Tx>", pTx, txLen);
    txnStatus = phNxpEse_Transceive(conn_ctx, &pCmdTrans, &pRspTrans);
    if ( txnStatus == ESESTATUS_SUCCESS )
    {
        *pRxLen = pRspTrans.len;
        LOG_MAU8_D("APDU Rx<", pRx, pRspTrans.len);
    }
    else
    {
        *pRxLen = 0;
        LOG_E(" Transcive Failed ");
        return SMCOM_SND_FAILED;
    }

    return SMCOM_OK;
}

U16 smComT1oI2C_AnswerToReset(void* conn_ctx, U8 *T1oI2Catr, U16 *T1oI2CatrLen)
{
    phNxpEse_data pRsp= {0};
    ESESTATUS txnStatus;
    U16 status = SMCOM_NO_ATR;

    ENSURE_OR_GO_EXIT(T1oI2Catr != NULL);
    ENSURE_OR_GO_EXIT(T1oI2CatrLen != NULL);
#if defined(T1oI2C_UM11225)
    txnStatus= phNxpEse_getAtr(conn_ctx, &pRsp);
#elif defined(T1oI2C_GP1_0)
    txnStatus= phNxpEse_getCip(conn_ctx, &pRsp);
#endif
    if(txnStatus == ESESTATUS_SUCCESS)
    {
        *T1oI2CatrLen = pRsp.len;
        if (pRsp.len > 0) {
            memcpy(T1oI2Catr, pRsp.p_data, pRsp.len);
            status = SMCOM_OK;
        }
        else {
            LOG_E(" ATR/CIP Length is improper!!!");
        }
    }
    else
    {
        *T1oI2CatrLen = 0;
        LOG_E(" Failed to Retrieve ATR/CIP status ");
    }
exit:
    return status;
}

U16 smComT1oI2C_ComReset(void* conn_ctx)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    status = phNxpEse_deInit(conn_ctx);
    if(status !=ESESTATUS_SUCCESS)
    {
        LOG_E("Failed to Reset 7816 protocol instance ");
        return SMCOM_COM_FAILED;
    }
    return SMCOM_OK;
}

#endif /* T1oI2C */
