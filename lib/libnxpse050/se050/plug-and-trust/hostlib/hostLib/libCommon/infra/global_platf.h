/*
* Copyright 2016,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _GLOBAL_PLATF_
#define _GLOBAL_PLATF_

#include "sm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLA_ISO7816                   (0x00)  //!< ISO7816-4 defined CLA byte

#define INS_GP_INITIALIZE_UPDATE      (0x50)  //!< Global platform defined instruction
#define INS_GP_EXTERNAL_AUTHENTICATE  (0x82)  //!< Global platform defined instruction
#define INS_GP_SELECT                 (0xA4)  //!< Global platform defined instruction
#define INS_GP_PUT_KEY                (0xD8)  //!< Global platform defined instruction

U16 GP_Select(void *conn_ctx, const U8 *appletName, U16 appletNameLen, U8 *response, U16 *responseLen);
U16 GP_GetCLAppletVersion(U8 *appletVersion, U16 *verionLength);
#ifdef __cplusplus
}
#endif
#endif
