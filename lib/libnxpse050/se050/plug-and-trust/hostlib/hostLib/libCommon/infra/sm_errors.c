/*
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
* @par Description
* This file implements generic APDU response evaluation.
* @par History
* 1.0   20-feb-2012 : Initial version
*
*****************************************************************************/

#include <stddef.h>
#include <assert.h>

#include "scp.h"
#include "sm_apdu.h"
#include "sm_errors.h"
#include "nxLog_hostLib.h"
#include "nxEnsure.h"

/**
* Returns the status word of a response APDU when no response data is expected.
* @param[in] pApdu Pointer to the APDU.
* @retval ::ERR_WRONG_RESPONSE In case the response contains more than only the status word
* @returns status word (in case the response is 2 byte long)
*/
U16 CheckNoResponseData(apdu_t * pApdu)
{
    U16 rv = ERR_GENERAL_ERROR;
    U8 isOk = 0x00;
    ENSURE_OR_GO_EXIT(pApdu != NULL);

    if (pApdu->rxlen != 2)
    {
        // printf("%d: pApdu->rxlen = %d", __LINE__, pApdu->rxlen);
        rv = ERR_WRONG_RESPONSE;
    }
    else
    {
        // printBytestring("CheckNoResponseData", pApdu->pBuf, pApdu->rxlen);
        rv = smGetSw(pApdu, &isOk);
    }

exit:
    return rv;
}

/**
* Returns the status word of a response APDU when no response data is expected.
* @param[in] rawResponse      Pointer to the raw response
* @param[in] rawResponseLen   Length of \p rawResponse
* @retval ::ERR_WRONG_RESPONSE In case the response contains more than only the status word
* @returns status word (in case the response is 2 byte long)
*/
U16 CheckNoResponseDataRaw(U8 *rawResponse, U16 rawResponseLen)
{
    U16 rv = ERR_GENERAL_ERROR;
    ENSURE_OR_GO_EXIT(rawResponse != NULL);

    if (rawResponseLen != 2)
    {
        rv = ERR_WRONG_RESPONSE;
    }
    else
    {
        rv = (rawResponse[0] << 8) + rawResponse[1];
    }

exit:
    return rv;
}
