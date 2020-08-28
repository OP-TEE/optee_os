/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot_int.h:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@appboot-top-eclipse_x86
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

#ifndef SSS_EX_SRC_EX_SSS_BOOT_INT_H_
#define SSS_EX_SRC_EX_SSS_BOOT_INT_H_

/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */
#include <ex_sss_boot.h>

#include "fsl_sss_se05x_apis.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Extern Variables
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Function Prototypes
 * ***************************************************************************************************************** */
#if SSS_HAVE_SE
sss_status_t ex_sss_boot_se_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

/** Entry Point for SE050 based build */

#if SSS_HAVE_APPLET_SE05X_IOT
sss_status_t ex_sss_boot_se05x_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_MBEDTLS
sss_status_t ex_sss_boot_mbedtls_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_OPENSSL
sss_status_t ex_sss_boot_openssl_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
sss_status_t ex_sss_boot_a71ch_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_A71CL || SSS_HAVE_SE050_L
sss_status_t ex_sss_boot_a71cl_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#endif /* SSS_EX_SRC_EX_SSS_BOOT_INT_H_ */
