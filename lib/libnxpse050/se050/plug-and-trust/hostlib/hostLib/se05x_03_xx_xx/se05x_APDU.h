/*
 * Copyright 2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef SE050X_APDU_H
#define SE050X_APDU_H

#ifdef __cplusplus
extern "C" {
#endif

#include "se05x_tlv.h"
#include "se05x_const.h"
#include "se05x_APDU_apis.h"

/** Se05x_API_DeleteAll_Iterative
 *
 * Go through each object and delete it individually.
 *
 * This API does not use the Applet API @ref Se05x_API_DeleteAll. It
 * does not delete ALL objects and purposefully skips few objects.
 *
 * Instead, this API uses @ref Se05x_API_ReadIDList and @ref
 * Se05x_API_ReadCryptoObjectList to first fetch list of objects to host, and
 * **selectitvely** deletes.
 *
 * For e.g. It does not kill objects from:
 *  - The range SE05X_OBJID_SE05X_APPLET_RES_START to
 *    SE05X_OBJID_SE05X_APPLET_RES_END.  This range is used by applet.
 *  - The range EX_SSS_OBJID_DEMO_AUTH_START to EX_SSS_OBJID_DEMO_AUTH_END,
 *    which is used by middleware DEMOS for authentication.
 *  - And others.
 *
 * Kindly see the Implementation of is API Se05x_API_DeleteAll_Iterative to see
 * the list of ranges that are skipped.
 *
 * @param[in]  session_ctx  Session Context
 *
 * @return     The status of API.
 */
smStatus_t Se05x_API_DeleteAll_Iterative(pSe05xSession_t session_ctx);

/**
 * @brief      Get the Curve ID for existing Key.
 *
 * This API is functionally same as @ref Se05x_API_GetECCurveId
 * but uses @ref SE05x_ECCurve_t as a type instead of uint8_t.
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  objectID     The object id
 * @param      pcurveId     The pcurve identifier
 *
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_EC_CurveGetId(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_ECCurve_t *pcurveId);

/** Wrapper for @ref Se05x_API_ECDHGenerateSharedSecret */

#define Se05x_API_ECGenSharedSecret Se05x_API_ECDHGenerateSharedSecret

/** Wrapper for @ref Se05x_API_DigestOneShot */
#define Se05x_API_SHAOneShot Se05x_API_DigestOneShot

// For SIMW-656
bool Se05x_IsInValidRangeOfUID(uint32_t uid);

#ifdef __cplusplus
}
#endif

#endif /* SE050X_APDU_H */
