/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
* @par Description
* This file is the communication specific Host API of the A70CM/CI and A71CH secure module.
* It also customizes the Generic Ax library for this specific product instance
* @par History
* 1.0   27-march-2014 : Initial version
*        7-may-2017   : Unified version for A70CM, CI and A71CH
*
*****************************************************************************/
#ifndef _SM_API_
#define _SM_API_

#include "sm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <PlugAndTrust_HostLib_Ver.h>

#define AX_HOST_LIB_MAJOR (PLUGANDTRUST_HOSTLIB_VER_MAJOR)  //!< Major number A71CH Host Library
#define AX_HOST_LIB_MINOR (PLUGANDTRUST_HOSTLIB_VER_MINOR)  //!< Minor (High Nibble)/Patch number (Low Nibble) of A71CH Host Library

/*!
* @addtogroup sss_sscp_a71ch
* @{
*/

#define SE_CONNECT_TYPE_START 0x000

typedef enum
{
    kType_SE_Conn_Type_NONE = 0,
    /** Used for A71XX Family */
    kType_SE_Conn_Type_SCII2C = SE_CONNECT_TYPE_START + 2,
    /** Used for PC/OSX for virtual COM Port */
    kType_SE_Conn_Type_VCOM = SE_CONNECT_TYPE_START + 3,
    /** Used for Legacy JRCP V1 protocol with iMX Linux Proxy */
    kType_SE_Conn_Type_JRCP_V1 = SE_CONNECT_TYPE_START + 4,
    /** Used for New JRCP Protocol */
    kType_SE_Conn_Type_JRCP_V2 = SE_CONNECT_TYPE_START + 5,
    /** Used for T=1 over I2C for SE050 family */
    kType_SE_Conn_Type_T1oI2C = SE_CONNECT_TYPE_START + 6,
    /** Used for Use NFC Interface to talk to SE */
    kType_SE_Conn_Type_NFC = SE_CONNECT_TYPE_START + 7,
    /** Used for Use a software layer to talk to SE
     * This logicaly allows double encryption of packets
     * from same host and allows multi-tenenancy
     *
     * Channel can be deemed as "Secure Channel" where applicable.
     *
     * Or it may be a plain "arbiter" to allow plain communication from
     * multiple threads on the same application.
     */
    kType_SE_Conn_Type_Channel = SE_CONNECT_TYPE_START + 8,

    kType_SE_Conn_Type_PCSC = SE_CONNECT_TYPE_START + 9,

    kType_SE_Conn_Type_LAST,
    kType_SE_Conn_Type_SIZE = 0x7FFF
} SSS_Conn_Type_t;

#define SELECT_APPLET 0 //!< Select predefined applet
#define SELECT_NONE   1 //!< Don't issue a select
#define SELECT_SSD    2 //!< Select SSD

/**
 * Contains the information required to resume a connection with the Security Module.
 * Its content is only to be interpreted by the Host Library.
 * The semantics of the param1 and param2 fields depends on the link layer.
 */
typedef struct {
    U16 connType;
    U16 param1;          //!< Useage depends on link layer
    U16 param2;          //!< Useage depends on link layer
    U16 hostLibVersion;  //!< MSByte contains major version (::AX_HOST_LIB_MAJOR); LSByte contains minor version of HostLib (::AX_HOST_LIB_MINOR)
    U32 appletVersion;   /*!< MSByte contains major version;
                              3 leading bits of LSByte contains minor version of Applet;
                              Last bit of LSByte encodes whether Applet is in Debug Mode, a '1' means 'Debug Mode' is available */
    U16 sbVersion;       //!< Expected to be 0x0000
    U8  select;          //!< Applet selection mode
} SmCommState_t;

/** \name Communication functions
   @{ */
U16 SM_Close(void *conn_ctx, U8 mode);
U16 SM_Connect(void *conn_ctx, SmCommState_t *commState, U8 *atr, U16 *atrLen);
U16 SM_ConnectWithAID(SmCommState_t *commState, U8* appletAID, U16 appletAIDLen, U8 *atr, U16 *atrLen);
U16 SM_RjctConnect(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *atr, U16 *atrLen);
U16 SM_RjctConnectWithAID(const char *connectString, SmCommState_t *commState, U8* appletAID, U16 appletAIDLen, U8 *atr, U16 *atrLen);
U16 SM_I2CConnect(void **conn_ctx, SmCommState_t *commState, U8 *atr, U16 *atrLen, const char *pConnString);

U16 SM_SendAPDU(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen);
/** @}*/

#ifdef __cplusplus
}
#endif
#endif //_SM_API_
