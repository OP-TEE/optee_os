/*
* Copyright 2019,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef SE05X_FTR_H
#define SE05X_FTR_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT

#include <Applet_SE050_Ver.h>

/** @def SE05X_FTR_8BIT_CURVE_ID
 *
 * Curve IDs are 8bit wide. Else, the follow same 32 bit
 * namespace.
 */

#if APPLET_SE050_VER_MAJOR_MINOR > 10002u
#define SE05X_FTR_8BIT_CURVE_ID (1)
#define SE05X_FTR_32BIT_CURVE_ID (0)
#else
#define SE05X_FTR_8BIT_CURVE_ID (0)
#define SE05X_FTR_32BIT_CURVE_ID (1)
#endif /* APPLET_SE050_VER_MAJOR_MINOR > 10002u */

#endif /* SSS_HAVE_APPLET_SE05X_IOT */

#endif /* SE05X_FTR_H */
