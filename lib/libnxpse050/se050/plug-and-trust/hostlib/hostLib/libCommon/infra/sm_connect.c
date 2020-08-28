/*
 * Copyright 2016-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
*
* @par History
* 1.0   1-oct-2016 : Initial version
*
*
*****************************************************************************/
/**
* @file sm_connect.c
* @par Description
* Implementation of basic communication functionality between Host and A71CH.
* (This file was renamed from ``a71ch_com.c`` into ``sm_connect.c``.)
*/

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <sm_const.h>
#include <smCom.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sm_api.h"
#include "sm_apdu.h"
#include "sm_errors.h"
#include "sm_types.h"

#include "nxLog_smCom.h"
#include "nxEnsure.h"

/// @cond

//Also do select after opening the connection
#define OPEN_AND_SELECT 0

/// @endcond

#ifdef TDA8029_UART
#include "smComAlpar.h"
#include "smUart.h"
#endif
#if defined(SCI2C)
#include "smComSCI2C.h"
#endif
#if defined(SPI)
#include "smComSCSPI.h"
#endif
#if defined(PCSC)
#include "smComPCSC.h"
#endif
#if defined(IPC)
#include "smComIpc.h"
#endif
#if defined(SMCOM_JRCP_V1)
#include "smComSocket.h"
#endif
#if defined(SMCOM_JRCP_V2)
#include "smComJRCP.h"
#endif
#if defined(RJCT_VCOM)
#include "smComSerial.h"
#endif
#if defined(T1oI2C)
#include "smComT1oI2C.h"
#endif
#if defined(SMCOM_PN7150)
#include "smComPN7150.h"
#endif
#if defined(SMCOM_THREAD)
#include "smComThread.h"
#endif
#if defined(SMCOM_PCSC)
#include "smComPCSC.h"
#endif
#if defined(SMCOM_RC663_VCOM)
#include "smComNxpNfcRdLib.h"
#endif

#include "global_platf.h"

/// @cond Optional diagnostics functionality
// #define FLOW_VERBOSE
#ifdef FLOW_VERBOSE
#define FPRINTF(...) printf(__VA_ARGS__)
#else
#define FPRINTF(...)
#endif
/// @endcond

#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
static U16 getSocketParams(const char *arg, U8 *szServer, U16 szServerLen, unsigned int *port)
{
    // the IP address is in format a.b.c.d:port, e.g. 10.0.0.1:8080
    int nSuccess;
    U16 rv = SW_OK;

    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(strlen(arg) < szServerLen, rv, ERR_BUF_TOO_SMALL);

    // First attempt at parsing: server IP-address passed, sscanf will return 2 upon successfull parsing
    nSuccess = sscanf(arg, "%15[0-9.]:%5u[0-9]", szServer, (unsigned int *)port);

    if (nSuccess == 2) {
        return SW_OK;
    }
    else {
        // Second attempt at parsing: server name passed instead of IP-address
        unsigned int i;
        int fColonFound = 0;

        for (i = 0; i < strlen(arg); i++) {
            if (arg[i] == ':') {
                szServer[i] = 0;
                fColonFound = 1;
                // PRINTF("servername: %s\r\n", szServer);
                break;
            }
            else {
                szServer[i] = arg[i];
            }
        }

        if ((fColonFound == 1) && (i != 0)) {
            nSuccess = sscanf(&arg[i], ":%5u[0-9]", (unsigned int *)port);
            ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(nSuccess != 1, rv, SW_OK);
        }
    }
    rv = ERR_NO_VALID_IP_PORT_PATTERN;
exit:
    return rv;
}

/**
* Establishes communication with the Security Module via a Remote JC Terminal Server
* (RJCT-Server).
* Next it will invoke ::SM_Connect and select the A71CH applet on the Secure Module
*
* \note Because connecting via an RJCT-server requires an extra parameter (the server IP:Port)
* an additional function is required on top of ::SM_Connect
*
* @param[in,out] connectString ip:port as string
* @param[in,out] commState
* @param[in,out] atr
* @param[in,out] atrLen
*
* @retval ::SW_OK Upon successful execution
*/
U16 SM_RjctConnectSocket(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
    U8 szServer[128];
    U16 szServerLen = sizeof(szServer);
    U16 rv = 0;
    unsigned int port = 0;
#if defined(SMCOM_JRCP_V2)
    char hostname[32] = {0};
#endif

#ifndef A71_IGNORE_PARAM_CHECK
    if ((connectString == NULL) || (commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }
#endif

    rv = getSocketParams(connectString, szServer, szServerLen, (unsigned int *)&port);

#if defined(SMCOM_JRCP_V1)
    FPRINTF("Connection to secure element over socket to %s\r\n", connectString);
    if (rv != SW_OK) {
        return rv;
    }
    // NOTE-MMA: The usage of the sss type kType_SE_Conn_Type_JRCP_V1 leads to a circular
    // dependency regarding the inclusion of header files.
    // if (commState->connType == kType_SE_Conn_Type_JRCP_V1) {
    rv = smComSocket_Open(conn_ctx, szServer, (U16)port, atr, atrLen);
    // }

#endif
#if defined(SMCOM_JRCP_V2)
    if (commState->connType == kType_SE_Conn_Type_JRCP_V2) {
        if (sizeof(hostname) < strlen(connectString)) {
            return ERR_API_ERROR;
        }
        strncpy(hostname, connectString, strlen(connectString));
        rv = smComJRCP_Open(conn_ctx, strtok(hostname, ":"), port);
    }

#endif
    if (rv != SMCOM_OK) {
        LOG_E("Error on smComSocket_Open: 0x%04X\r\n", rv);
        return rv;
    }

    if (conn_ctx == NULL) {
        rv = SM_Connect(NULL, commState, atr, atrLen);
    }
    else {
        rv = SM_Connect(*conn_ctx, commState, atr, atrLen);
    }

    return rv;
}
#endif /* defined(SMCOM_JRCP_V1) || defined (SMCOM_JRCP_V2) */

#ifdef RJCT_VCOM
U16 SM_RjctConnectVCOM(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
    U32 status;

#ifndef A71_IGNORE_PARAM_CHECK
    if ((connectString == NULL) || (commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }
#endif

    status = smComVCom_Open(conn_ctx, connectString);

    if (status == 0) {
        if (conn_ctx == NULL) {
            status = smComVCom_GetATR(NULL, atr, atrLen);
            if (status == 0) {
                status = (U16)SM_Connect(NULL, commState, atr, atrLen);
                if (status != SMCOM_OK) {
                    SM_Close(NULL, 0);
                }
            }
            else {
                SM_Close(NULL, 0);
            }
        }
        else {
            status = smComVCom_GetATR(*conn_ctx, atr, atrLen);
            if (status == 0) {
                status = (U16)SM_Connect(*conn_ctx, commState, atr, atrLen);
            }
            else {
                SM_Close(NULL, 0);
            }
        }
    }
    else {
        *atrLen = 0;
    }

    return (U16)status;
}
#endif // RJCT_VCOM

#ifdef SMCOM_RC663_VCOM
U16 SM_RjctConnectNxpNfcRdLib(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
    U32 status;

    if ((connectString == NULL) || (commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }

    status = smComNxpNfcRdLib_OpenVCOM(conn_ctx, connectString);

    if (status == 0) {
        status = (U16)SM_Connect(conn_ctx, commState, atr, atrLen);
    }
    else {
        *atrLen = 0;
    }
    if (status == SMCOM_OK) {
        *atrLen = 0;
    }

    return (U16)status;
}
#endif

#ifdef SMCOM_PCSC
U16 SM_RjctConnectPCSC(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
    U32 status = SMCOM_OK;

#ifndef A71_IGNORE_PARAM_CHECK
    if ( //(connectString == NULL) ||
        (commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }
#endif

    status = smComPCSC_Open(connectString);

    if (status == SMCOM_OK) {
        if (conn_ctx == NULL) {
            status = (U16)SM_Connect(NULL, commState, atr, atrLen);
        }
        else {
            status = (U16)SM_Connect(*conn_ctx, commState, atr, atrLen);
        }
    }
    else {
        *atrLen = 0;
    }

    return (U16)status;
}
#endif // RJCT_VCOM

U16 SM_RjctConnect(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
#if RJCT_VCOM || SMCOM_JRCP_V1 || SMCOM_JRCP_V2 || SMCOM_RC663_VCOM
    bool is_socket = FALSE;
    bool is_vcom = FALSE;
    AX_UNUSED_ARG(is_socket);
    AX_UNUSED_ARG(is_vcom);
#endif

#if RJCT_VCOM || SMCOM_RC663_VCOM
    if (NULL == connectString) {
        is_vcom = FALSE;
    }
    else if (0 == strncmp("COM", connectString, sizeof("COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("\\\\.\\COM", connectString, sizeof("\\\\.\\COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/tty/", connectString, sizeof("/tty/") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/dev/tty", connectString, sizeof("/dev/tty") - 1)) {
        is_vcom = TRUE;
    }
#endif
#if SMCOM_JRCP_V1 || SMCOM_JRCP_V2
    if (NULL == connectString) {
        LOG_W("connectString is NULL. Aborting.");
        return ERR_NO_VALID_IP_PORT_PATTERN;
    }
    if (NULL != strchr(connectString, ':')) {
        is_socket = TRUE;
    }
#endif
#if RJCT_VCOM
    if (is_vcom) {
        return SM_RjctConnectVCOM(conn_ctx, connectString, commState, atr, atrLen);
    }
    else {
        LOG_W("Build is compiled for VCOM. connectString='%s' does not look like COMPort",connectString);
        LOG_W("e.g. connectString are COM3, \\\\.\\COM5, /dev/tty.usbmodem1432301, etc.");
    }
#endif
#if SMCOM_RC663_VCOM
    if (is_vcom) {
        return SM_RjctConnectNxpNfcRdLib(conn_ctx, connectString, commState, atr, atrLen);
    }
    else {
        LOG_W("Build is compiled for RC663_VCOM. connectString='%s' does not look like COMPort",connectString);
        LOG_W("e.g. connectString are COM3, \\\\.\\COM5, /dev/tty.usbmodem1432301, etc.");
    }
#endif
#if SMCOM_JRCP_V1 || SMCOM_JRCP_V2
    if (is_socket) {
        return SM_RjctConnectSocket(conn_ctx, connectString, commState, atr, atrLen);
    }
#endif
#if SMCOM_PCSC
    if (NULL != commState) {
        return SM_RjctConnectPCSC(conn_ctx, connectString, commState, atr, atrLen);
    }
#endif
    LOG_W(
        "Can not use connectString='%s' in the current build configuration.\n\tPlease select correct smCom interface "
        "and re-compile!\n",
        connectString);
    return ERR_NO_VALID_IP_PORT_PATTERN;
}

#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2) || defined(RJCT_VCOM) || \
    defined(SMCOM_PCSC)
#else
U16 SM_I2CConnect(void **conn_ctx, SmCommState_t *commState, U8 *atr, U16 *atrLen, const char *pConnString)
{
    U16 status = SMCOM_COM_FAILED;
#if defined(T1oI2C)
    status = smComT1oI2C_Init(conn_ctx, pConnString);
#elif defined (SCI2C)
    status = smComSCI2C_Init(conn_ctx, pConnString);
#endif
    if (status != SMCOM_OK) {
        return status;
    }
    if (conn_ctx == NULL) {
        return SM_Connect(NULL, commState, atr, atrLen);
    }
    else {
        return SM_Connect(*conn_ctx, commState, atr, atrLen);
    }
}
#endif

/**
* Establishes the communication with the Security Module (SM) at the link level and
* selects the A71CH applet on the SM. The physical communication layer used (e.g. I2C)
* is determined at compilation time.
*
* @param[in,out] commState
* @param[in,out] atr
* @param[in,out] atrLen
*
* @retval ::SW_OK Upon successful execution
*/
U16 SM_Connect(void *conn_ctx, SmCommState_t *commState, U8 *atr, U16 *atrLen)
{
    U16 sw = SW_OK;
#if !defined(IPC)

#ifdef APPLET_NAME
    unsigned char appletName[] = APPLET_NAME;
#endif // APPLET_NAME
#ifdef SSD_NAME
    unsigned char ssdName[] = SSD_NAME;
#endif
    U16 selectResponseDataLen = 0;
    U8 selectResponseData[256] = {0};
    U16 uartBR = 0;
    U16 t1BR = 0;
#endif
#ifdef TDA8029_UART
    U32 status = 0;
#endif

#ifndef A71_IGNORE_PARAM_CHECK
    ENSURE_OR_EXIT_WITH_STATUS_ON_ERROR(((commState != NULL) && (atr != NULL) && (atrLen != 0)), sw, ERR_API_ERROR)
#endif

#ifdef TDA8029_UART
    if ((*atrLen) <= 33)
        return ERR_API_ERROR;

    smComAlpar_Init();
    status = smComAlpar_AtrT1Configure(ALPAR_T1_BAUDRATE_MAX, atr, atrLen, &uartBR, &t1BR);
    if (status != SMCOM_ALPAR_OK) {
        commState->param1 = 0;
        commState->param2 = 0;
        FPRINTF("smComAlpar_AtrT1Configure failed: 0x%08X\r\n", status);
        return ERR_CONNECT_LINK_FAILED;
    }
#elif defined SMCOM_PN7150
    sw = smComPN7150_Open(0, 0x00, atr, atrLen);
#elif defined(SCI2C)
    sw = smComSCI2C_Open(conn_ctx, ESTABLISH_SCI2C, 0x00, atr, atrLen);
#elif defined(SPI)
    smComSCSPI_Init(ESTABLISH_SCI2C, 0x00, atr, atrLen);
#elif defined(IPC)
    sw = smComIpc_Open(atr, atrLen, &(commState->hostLibVersion), &(commState->appletVersion), &(commState->sbVersion));
#elif defined(T1oI2C)
    sw = smComT1oI2C_Open(conn_ctx, ESE_MODE_NORMAL, 0x00, atr, atrLen);
#elif defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2) || defined(PCSC) || defined(SMCOM_PCSC)
    if (atrLen != NULL)
        *atrLen = 0;
    AX_UNUSED_ARG(atr);
    AX_UNUSED_ARG(atrLen);
#elif defined(RJCT_VCOM)
#elif defined(SMCOM_THREAD)
    sw = smComThread_Open(atr, atrLen);
#endif // TDA8029_UART

#if !defined(IPC)
    commState->param1 = t1BR;
    commState->param2 = uartBR;
    commState->hostLibVersion = (AX_HOST_LIB_MAJOR << 8) + AX_HOST_LIB_MINOR;
    commState->appletVersion = 0xFFFF;
    commState->sbVersion = 0xFFFF;

#ifdef APPLET_NAME
    if (sw == SMCOM_OK) {
        selectResponseDataLen = sizeof(selectResponseData);
        /* CARD */
        if (commState->select == SELECT_NONE) {
            /* Use Case just Connect to SE (smCom) and no kind of applet selection */
            sw = SMCOM_OK;
            selectResponseDataLen = 0;
        }
        else if (commState->select == SELECT_SSD) {
#ifdef SSD_NAME
            /* Rotate keys Use Case Connect to SE and Select SSD */
            /* Select SSD */
            sw = GP_Select(conn_ctx, (U8 *)&ssdName, sizeof(ssdName), selectResponseData, &selectResponseDataLen);
#else
            sw = SMCOM_COM_FAILED;
#endif
        }
        else
        {
            /* Select card manager */
            GP_Select(conn_ctx, (U8 *)&appletName, 0, selectResponseData, &selectResponseDataLen);
            selectResponseDataLen = sizeof(selectResponseData);
            /* Select the applet */
            sw = GP_Select(conn_ctx, (U8 *)&appletName, APPLET_NAME_LEN, selectResponseData, &selectResponseDataLen);
        }

        if (sw == SW_FILE_NOT_FOUND) {
            // Applet can not be selected (most likely it is simply not installed)
            LOG_E("Can not select Applet=%s'", SE_NAME);
            LOG_MAU8_E("Failed (SW_FILE_NOT_FOUND) selecting Applet. ", appletName, APPLET_NAME_LEN);
            return sw;
        }
        else if (sw != SW_OK) {
            LOG_E("SM_CONNECT Failed.");
            sw = ERR_CONNECT_SELECT_FAILED;
        }
        else {
#ifdef FLOW_VERBOSE
            if (selectResponseDataLen > 0) {
                LOG_MAU8_I("selectResponseData", selectResponseData, selectResponseDataLen);
            }
#endif // FLOW_VERBOSE
#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
            if (selectResponseDataLen >= 2) {
                commState->appletVersion = (selectResponseData[0] << 8) + selectResponseData[1];
                if (selectResponseDataLen == 4) {
                    commState->sbVersion = (selectResponseData[2] << 8) + selectResponseData[3];
                }
                else if (selectResponseDataLen == 2) {
                    commState->sbVersion = 0x0000;
                }
            }
            else {
                sw = ERR_CONNECT_SELECT_FAILED;
            }
#elif SSS_HAVE_A71CL
            if (selectResponseDataLen == 0) {
                commState->appletVersion = 0;
                commState->sbVersion = 0x0000;
            }
#endif // SSS_HAVE_A71CH / SSS_HAVE_A71CL
#if SSS_HAVE_SE05X
            if (selectResponseDataLen == 5 || selectResponseDataLen == 4 || selectResponseDataLen == 7) {
                // 2.2.4 returns 4 bytes, 2.2.4.[A,B,C]
                // 2.3.0 returns 5 bytes, 2.3.0.[v1].[v2]
                // 2.5.3 returns 7 bytes,
                commState->appletVersion = 0;
                commState->appletVersion |= selectResponseData[0];
                commState->appletVersion <<= 8;
                commState->appletVersion |= selectResponseData[1];
                commState->appletVersion <<= 8;
                commState->appletVersion |= selectResponseData[2];
                commState->appletVersion <<= 8;
                // commState->appletVersion |= selectResponseData[3];
                commState->sbVersion = 0x0000;
            }
            else {
            }
#endif // SSS_HAVE_SE05X
        }
    }
#endif /* Applet Name*/
#endif // !defined(IPC)
exit:
    return sw;
}

/**
 * Closes the communication with the Security Module
 * A new connection can be established by calling ::SM_Connect
 *
 * @param[in] mode Specific information that may be required on the link layer
 *
 * @retval ::SW_OK Upon successful execution
 */
U16 SM_Close(void *conn_ctx, U8 mode)
{
    U16 sw = SW_OK;

#if defined(SCI2C)
    sw = smComSCI2C_Close(mode);
#endif
#if defined(SPI)
    sw = smComSCSPI_Close(mode);
#endif
#if defined(PCSC)
    sw = smComPCSC_Close(mode);
#endif
#if defined(IPC)
    AX_UNUSED_ARG(mode);
    sw = smComIpc_Close();
#endif
#if defined(T1oI2C)
    sw = smComT1oI2C_Close(conn_ctx, mode);
#endif
#if defined(SMCOM_JRCP_V1)
    AX_UNUSED_ARG(mode);
    sw = smComSocket_Close();
#endif
#if defined(SMCOM_JRCP_V2)
    AX_UNUSED_ARG(mode);
    sw = smComJRCP_Close(conn_ctx, mode);
#endif
#if defined(RJCT_VCOM)
    AX_UNUSED_ARG(mode);
    sw = smComVCom_Close(conn_ctx);
#endif
#if defined(SMCOM_THREAD)
    AX_UNUSED_ARG(mode);
    sw = smComThread_Close();
#endif
#if defined(SMCOM_RC663_VCOM)
    AX_UNUSED_ARG(mode);
    smComNxpNfcRdLib_Close();
#endif
    smCom_DeInit();

    return sw;
}

/**
 * Sends the command APDU to the Secure Module and retrieves the response APDU.
 * The latter consists of the concatenation of the response data (possibly none) and the status word (2 bytes).
 *
 * The command APDU and response APDU are not interpreted by the host library.
 *
 * The command/response APDU sizes must lay within the APDU size limitations
 *
 * @param[in] cmd   command APDU
 * @param[in] cmdLen length (in byte) of \p cmd
 * @param[in,out] resp  response APDU (response data || response status word)
 * @param[in,out] respLen IN: Length of resp buffer (\p resp) provided; OUT: effective length of response retrieved.
 *
 * @retval ::SW_OK Upon successful execution
 */
U16 SM_SendAPDU(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen)
{
    U32 status = 0;
    U32 respLenLocal;

#ifndef A71_IGNORE_PARAM_CHECK
    ENSURE_OR_RETURN_ON_ERROR(((cmd != NULL) && (resp != NULL) && (respLen != NULL)), ERR_API_ERROR);
#endif

    respLenLocal = *respLen;

    status = smCom_TransceiveRaw(NULL, cmd, cmdLen, resp, &respLenLocal);
    *respLen = (U16)respLenLocal;

    return (U16)status;
}

#if defined(IPC)
U16 SM_LockChannel()
{
    return smComIpc_LockChannel();
}

U16 SM_UnlockChannel()
{
    return smComIpc_UnlockChannel();
}
#endif
