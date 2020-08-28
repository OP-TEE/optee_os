/*
* Copyright 2019,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef SE05X_ECC_CURVES_H_INC
#define SE05X_ECC_CURVES_H_INC

#include "se05x_tlv.h"

#define PROCESS_ECC_CURVE(NAME) \
    smStatus_t Se05x_API_CreateCurve_##NAME(Se05xSession_t *pSession, uint32_t obj_id)

#include <se05x_ecc_curves_inc.h>

#undef PROCESS_ECC_CURVE

#endif
