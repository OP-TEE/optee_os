/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <se05x_const.h>
#include <se05x_APDU.h>
#include <nxLog_hostLib.h>
//#include <ex_sss_auth.h>
#include <ex_sss_objid.h>
#include <smCom.h>
#include <string.h>
#include "sm_const.h"
#include "nxEnsure.h"
#include <fsl_sss_api.h>
// For SIMW-656
// #include "../../sss/ex/inc/ex_sss_objid.h"

#if APPLET_SE050_VER_MAJOR_MINOR >= 20000u

smStatus_t Se05x_API_DeleteAll_Iterative(pSe05xSession_t session_ctx)
{
    uint8_t pmore = kSE05x_MoreIndicator_NA;
    uint8_t list[1024];
    size_t listlen = sizeof(list);
    size_t i;
    smStatus_t retStatus  = SM_NOT_OK;
    uint16_t outputOffset = 0;
    do {
        retStatus = Se05x_API_ReadIDList(session_ctx, outputOffset, 0xFF, &pmore, list, &listlen);
        if (retStatus != SM_OK) {
            return retStatus;
        }
        outputOffset = (uint16_t)listlen;
        for (i = 0; i < listlen; i += 4) {
            uint32_t id = 0 | (list[i + 0] << (3 * 8)) | (list[i + 1] << (2 * 8)) | (list[i + 2] << (1 * 8)) |
                          (list[i + 3] << (0 * 8));
            if (SE05X_OBJID_SE05X_APPLET_RES_START == SE05X_OBJID_SE05X_APPLET_RES_MASK(id)) {
                LOG_D("Not erasing ObjId=0x%08X (Reserved)", id);
                /* In Reserved space */
            }
            else if (EX_SSS_OBJID_DEMO_AUTH_START == EX_SSS_OBJID_DEMO_AUTH_MASK(id)) {
                LOG_D("Not erasing ObjId=0x%08X (Demo Auth)", id);
                /* Not reasing default authentication object */
            }
            else if (EX_SSS_OBJID_IOT_HUB_A_START == EX_SSS_OBJID_IOT_HUB_A_MASK(id)) {
                LOG_D("Not erasing ObjId=0x%08X (IoT Hub)", id);
                /* Not reasing IoT Hub object */
            }
            else if (!SE05X_OBJID_TP_MASK(id) && id) {
                LOG_D("Not erasing Trust Provisioned objects");
            }
            else {
                retStatus = Se05x_API_DeleteSecureObject(session_ctx, id);
                if (retStatus != SM_OK) {
                    LOG_W("Error in erasing ObjId=0x%08X (Others)", id);
                }
            }
        }
    } while (pmore == kSE05x_MoreIndicator_MORE);
#if SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ
    retStatus = Se05x_API_ReadCryptoObjectList(session_ctx, list, &listlen);
    if (retStatus != SM_OK) {
        goto cleanup;
    }
    for (i = 0; i < listlen; i += 4) {
        uint16_t cryptoObjectId = list[i + 1] | (list[i + 0] << 8);
        retStatus               = Se05x_API_DeleteCryptoObject(session_ctx, cryptoObjectId);
        if (retStatus != SM_OK) {
            LOG_W("Error in erasing CryptoObject=%04X", cryptoObjectId);
        }
    }
cleanup:
#endif
    return retStatus;
}

#endif

bool Se05x_IsInValidRangeOfUID(uint32_t uid)
{
#if 0
    // For SIMW-656
    bool retVal = TRUE;
    if (uid >= EX_SSS_OBJID_DEMO_START && uid <= EX_SSS_OBJID_DEMO_END)
    {
        retVal = FALSE;
    }
    else if (uid >= SE05X_OBJID_SE05X_APPLET_RES_START && uid <= SE05X_OBJID_SE05X_APPLET_RES_END)
    {
        retVal = FALSE;
    }
    else if (uid >= EX_SSS_OBJID_TEST_START && uid <= EX_SSS_OBJID_TEST_END)
    {
        retVal = FALSE;
    }
    if (retVal == TRUE) {
        LOG_E("Not allowing 0x%X uid", uid);
    }
    return retVal;
#else
    return FALSE;
#endif
}
