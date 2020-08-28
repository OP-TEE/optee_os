/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * This file provides the API of the SmCom T1oI2C communication layer.
 *
 *****************************************************************************/

#ifndef _SMCOMT1OI2C_H_
#define _SMCOMT1OI2C_H_

#include "smCom.h"

/**
 * \ingroup spi_libese
 * \brief Ese Channel mode
 *
 */
typedef enum
{
    ESE_MODE_NORMAL = 0, /*!< All wired transaction other OSU */
    ESE_MODE_OSU /*!< Jcop Os update mode */
} phNxpEse_initMode;

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * closes  the T=1 o I2C communication layer.
 * @param conn_ctx  connection context
 * @param mode      Ese Communication mode either
 *                  ESE_MODE_NORMAL: All wired transaction other OSU or
 *                  ESE_MODE_OSU :Jcop Os update mode
 * @return
 */
U16 smComT1oI2C_Close(void *conn_ctx, U8 mode);

/**
 * @param conn_ctx  connection context
 * Reset  the T=1 o protocol instance.
 * @return
 */
U16 smComT1oI2C_ComReset(void *conn_ctx);

/**
 * Initializes or resumes the T=1 o I2C communication layer.
 * @param conn_ctx      IN: connection context
 * @param mode          Ese Communication mode either ESE_MODE_NORMAL: All wired transaction other OSU or ESE_MODE_OSU :Jcop Os update mode
 * @param T1oI2Catr     IN: Pointer to buffer to contain SCI2C_ATR value
 * @param T1oI2CatrLen  IN: Size of buffer provided; OUT: Actual length of atr retrieved
 * @return
 */
U16 smComT1oI2C_Open(void *conn_ctx, U8 mode, U8 seqCnt, U8 *T1oI2Catr, U16 *T1oI2CatrLen);

/**
* Open I2C device.
* @param conn_ctx      IN: pointer connection context
* @param pConnParam    IN: I2C address
* @return
*/
U16 smComT1oI2C_Init(void **conn_ctx, const char *pConnString);

#if defined(__cplusplus)
}
#endif
#endif /* _SMCOMT1OI2C_H_ */
