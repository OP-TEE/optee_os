/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sm_types.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_SE05X && SSSFTR_SE05X_ECC

#include "se05x_ecc_curves.h"
#include "se05x_APDU.h"

#include "se05x_ecc_curves_values.h"
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / (sizeof(array[0])))
#endif

#define PROCESS_ECC_CURVE(NAME)                                                                                      \
    smStatus_t Se05x_API_CreateCurve_##NAME(Se05xSession_t *pSession, uint32_t obj_id)                               \
    {                                                                                                                \
        smStatus_t status;                                                                                           \
        const uint8_t ecc_prime[]  = {EC_PARAM_##NAME##_prime};                                                      \
        const uint8_t ecc_a[]      = {EC_PARAM_##NAME##_a};                                                          \
        const uint8_t ecc_b[]      = {EC_PARAM_##NAME##_b};                                                          \
        const uint8_t ecc_G[]      = {0x04, EC_PARAM_##NAME##_x, EC_PARAM_##NAME##_y};                               \
        const uint8_t ecc_ordern[] = {EC_PARAM_##NAME##_order};                                                      \
                                                                                                                     \
        status = Se05x_API_CreateECCurve(pSession, obj_id);                                                          \
        if (status != SM_OK) {                                                                                       \
            return status;                                                                                           \
        }                                                                                                            \
                                                                                                                     \
        status = Se05x_API_SetECCurveParam(pSession, obj_id, kSE05x_ECCurveParam_PARAM_A, ecc_a, ARRAY_SIZE(ecc_a)); \
        if (status != SM_OK) {                                                                                       \
            return status;                                                                                           \
        }                                                                                                            \
                                                                                                                     \
        status = Se05x_API_SetECCurveParam(pSession, obj_id, kSE05x_ECCurveParam_PARAM_B, ecc_b, ARRAY_SIZE(ecc_b)); \
        if (status != SM_OK) {                                                                                       \
            return status;                                                                                           \
        }                                                                                                            \
                                                                                                                     \
        status = Se05x_API_SetECCurveParam(pSession, obj_id, kSE05x_ECCurveParam_PARAM_G, ecc_G, ARRAY_SIZE(ecc_G)); \
        if (status != SM_OK) {                                                                                       \
            return status;                                                                                           \
        }                                                                                                            \
                                                                                                                     \
        status = Se05x_API_SetECCurveParam(                                                                          \
            pSession, obj_id, kSE05x_ECCurveParam_PARAM_N, ecc_ordern, ARRAY_SIZE(ecc_ordern));                      \
        if (status != SM_OK) {                                                                                       \
            return status;                                                                                           \
        }                                                                                                            \
                                                                                                                     \
        status = Se05x_API_SetECCurveParam(                                                                          \
            pSession, obj_id, kSE05x_ECCurveParam_PARAM_PRIME, ecc_prime, ARRAY_SIZE(ecc_prime));                    \
        return status;                                                                                               \
    }

#include "se05x_ecc_curves_inc.h"

#endif
