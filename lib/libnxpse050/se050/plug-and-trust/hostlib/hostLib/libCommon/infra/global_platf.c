/*
* Copyright 2016,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "global_platf.h"
#include "smCom.h"

#include "scp.h"
#include "sm_apdu.h"
#include "sm_errors.h"

#include "nxLog_hostLib.h"
#include "nxEnsure.h"

/**
 * Send a select command to the card manager
 *
 * \param[in] appletName Pointer to a buffer containing the applet name.
 * \param[in] appletNameLen Length of the applet name.
 * \param[out] responseData Pointer to a buffer that will contain response data (excluding status word).
 * \param[in,out] responseDataLen IN: size of pResponse buffer passed as argument; OUT: Length of response data retrieved
 *
 * \retval ::SW_OK Upon successfull execution
 */
U16 GP_Select(void *conn_ctx, const U8 *appletName, U16 appletNameLen, U8 *responseData, U16 *responseDataLen)
{
    U16 rv = ERR_COMM_ERROR;
    U32 u32RXLen = *responseDataLen;

    uint8_t tx_buf[MAX_APDU_BUF_LENGTH];
    uint16_t tx_len;

    ENSURE_OR_GO_CLEANUP(NULL != responseData);
    ENSURE_OR_GO_CLEANUP(0 != responseDataLen);
    ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
    /* cla+ins+p1+p2+lc+appletNameLen+le */
    ENSURE_OR_GO_CLEANUP(sizeof(tx_buf) > (6 + appletNameLen));

    tx_buf[0] = CLA_ISO7816;
    tx_buf[1] = INS_GP_SELECT;
    tx_buf[2] = 4;
    tx_buf[3] = 0;

    tx_len = 0   /* for indentation */
             + 1 /* CLA */
             + 1 /* INS */
             + 1 /* P1 */
             + 1 /* P2 */;
    if (appletNameLen > 0) {
        tx_buf[4] = (uint8_t)appletNameLen; // We have done ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
        tx_len = tx_len + 1      /* Lc */
                 + appletNameLen /* Payload */
                 + 1 /* Le */;
        memcpy(&tx_buf[5], appletName, appletNameLen);
    }
    else {
        tx_len = tx_len /* for indentation */
                 + 0    /* No Lc */
                 + 1 /* Le */;
    }
    tx_buf[tx_len - 1] = 0; /* Le */

    // apdu_t * pApdu = (apdu_t *) &apdu;
    // U8 isOk = 0x00;

    // pApdu->cla   = CLA_ISO7816;
    // pApdu->ins   = INS_GP_SELECT;
    // pApdu->p1    = 0x04;
    // pApdu->p2    = 0x00;

    rv = smCom_TransceiveRaw(conn_ctx, tx_buf, tx_len, responseData, &u32RXLen);
    if (rv == SW_OK && u32RXLen >= 2) {
        *responseDataLen = u32RXLen - 2;
        rv = responseData[u32RXLen - 2];
        rv <<= 8;
        rv |= responseData[u32RXLen - 1];
    }

cleanup:
    return rv;
}
