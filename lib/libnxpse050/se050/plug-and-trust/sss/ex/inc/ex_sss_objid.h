/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_objid.h:  Reserved Object Identifiers
 *
 * Project:  SecureIoTMW-Debug@simw-top-eclipse_x86
 *
 * $Date: Mar 27, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

#ifndef SSS_EX_INC_EX_SSS_OBJID_H_
#define SSS_EX_INC_EX_SSS_OBJID_H_

/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */

/* clang-format off */
#define EX_SSS_OBJID_CUST_START             0x00000001u
#define SE05X_OBJID_TP_MASK(X)              (0xFFFFFFFC & (X))
#define EX_SSS_OBJID_CUST_END               0x7BFFFFFFu

#define EX_SSS_OBJID_AKM_START             0x7C000000u
#define EX_SSS_OBJID_AKM_END               0x7CFFFFFFu

#define EX_SSS_OBJID_DEMO_START             0x7D000000u
#define EX_SSS_OBJID_DEMO_SA_START              0x7D500000u
#define EX_SSS_OBJID_DEMO_WIFI_START                0x7D51F000u
/* doc:start:mif-kdf-start-keyid */
#define EX_SSS_OBJID_DEMO_MFDF_START                0x7D5DF000u
/* doc:end:mif-kdf-start-keyid */
/////// EX_SSS_OBJID_DEMO_SA_END                0x7D5FFFFFu
#define EX_SSS_OBJID_DEMO_AUTH_START            0x7DA00000u
#define EX_SSS_OBJID_DEMO_AUTH_MASK(X)         (0xFFFF0000u & (X))
/////// EX_SSS_OBJID_DEMO_AUTH_END              0x7DA0FFFFu
#define EX_SSS_OBJID_DEMO_CLOUD_START           0x7DC00000u
#define EX_SSS_OBJID_DEMO_CLOUD_IBM_START           0x7DC1B000u
#define EX_SSS_OBJID_DEMO_CLOUD_GCP_START           0x7DC6C000u
#define EX_SSS_OBJID_DEMO_CLOUD_AWS_START           0x7DCA5000u
#define EX_SSS_OBJID_DEMO_CLOUD_AZURE_START         0x7DCAC000u
/////// EX_SSS_OBJID_DEMO_CLOUD_END             0x7DCFFFFFu
#define EX_SSS_OBJID_DEMO_END               0x7DFFFFFFu
#define SE05X_OBJID_SE05X_APPLET_RES_START  0x7FFF0000u
#define SE05X_OBJID_SE05X_APPLET_RES_MASK(X) \
                                           (0xFFFF0000u & (X))
#define SE05X_OBJID_SE05X_APPLET_RES_END    0x7FFFFFFFu

/* IoT Hub Managed */
#define SE05X_OBJID_IOT_HUB_M_START         0x80000000u
#define SE05X_OBJID_IOT_HUB_M_END           0xEEFFFFFFu
#define EX_SSS_OBJID_TEST_START             0xEF000000u
#define EX_SSS_OBJID_TEST_END               0xEFFFFFFFu

/* IoT Hub Access */
#define EX_SSS_OBJID_IOT_HUB_A_START        0xF0000000u
#define EX_SSS_OBJID_IOT_HUB_A_MASK(X)     (0xF0000000u & (X))

//Device Key and Certificate - ECC-256
#define EX_SSS_OBJID_TP_KEY_EC_D                   0xF0000100
#define EX_SSS_OBJID_TP_CERT_EC_D                  0xF0000101
//Gateway Key and Certificate - ECC-256
#define EX_SSS_OBJID_TP_KEY_EC_G                   0xF0000102
#define EX_SSS_OBJID_TP_CERT_EC_G                  0xF0000103

//Device Key and Certificate - RSA-2K
#define EX_SSS_OBJID_TP_KEY_RSA2K_D                0xF0000110
#define EX_SSS_OBJID_TP_CERT_RSA2K_D               0xF0000111
//Gateway Key and Certificate - RSA-2K
#define EX_SSS_OBJID_TP_KEY_RSA2K_G                0xF0000112
#define EX_SSS_OBJID_TP_CERT_RSA2K_G               0xF0000113
//Device Key and Certificate - RSA-4K
#define EX_SSS_OBJID_TP_KEY_RSA4K_D                0xF0000120
#define EX_SSS_OBJID_TP_CERT_RSA4K_D               0xF0000121
//Gateway Key and Certificate - RSA-4K
#define EX_SSS_OBJID_TP_KEY_RSA4K_G                0xF0000122
#define EX_SSS_OBJID_TP_CERT_RSA4K_G               0xF0000123

#define EX_SSS_OBJID_IOT_HUB_A_END          0xFFFFFFFFu

/* clang-format on */

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */

enum
{
    kEX_SSS_ObjID_UserID_Auth = EX_SSS_OBJID_DEMO_AUTH_START + 1,
    kEX_SSS_ObjID_APPLETSCP03_Auth,
    kEX_SSS_objID_ECKEY_Auth,
};

/* *****************************************************************************************************************
 *   Extern Variables
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Function Prototypes
 * ***************************************************************************************************************** */

#endif /* SSS_EX_INC_EX_SSS_OBJID_H_ */
