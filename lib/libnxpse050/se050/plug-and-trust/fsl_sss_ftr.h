/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_FTR_H_
#define SSS_APIS_INC_FSL_SSS_FTR_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* clang-format off */


/* # CMake Features : Start */


/** Applet : The Secure Element Applet
 *
 * You can compile host library for different Applets listed below.
 * Please note, some of these Applets may be for NXP Internal use only.
 */

/** Compiling without any Applet Support */
#define SSS_HAVE_APPLET_NONE 0

/** A71CH (ECC) */
#define SSS_HAVE_APPLET_A71CH 0

/** A71CL (RSA) */
#define SSS_HAVE_APPLET_A71CL 0

/** Similar to A71CH */
#define SSS_HAVE_APPLET_A71CH_SIM 0

/** SE050 Type A (ECC) */
#define SSS_HAVE_APPLET_SE05X_A 0

/** SE050 Type B (RSA) */
#define SSS_HAVE_APPLET_SE05X_B 0

/** SE050 (Super set of A + B) */
#define SSS_HAVE_APPLET_SE05X_C 1

/** SE050 (Similar to A71CL) */
#define SSS_HAVE_APPLET_SE05X_L 0

/** NXP Internal testing Applet */
#define SSS_HAVE_APPLET_LOOPBACK 0

#if (( 0                             \
    + SSS_HAVE_APPLET_NONE           \
    + SSS_HAVE_APPLET_A71CH          \
    + SSS_HAVE_APPLET_A71CL          \
    + SSS_HAVE_APPLET_A71CH_SIM      \
    + SSS_HAVE_APPLET_SE05X_A        \
    + SSS_HAVE_APPLET_SE05X_B        \
    + SSS_HAVE_APPLET_SE05X_C        \
    + SSS_HAVE_APPLET_SE05X_L        \
    + SSS_HAVE_APPLET_LOOPBACK       \
    ) > 1)
#        error "Enable only one of 'Applet'"
#endif


#if (( 0                             \
    + SSS_HAVE_APPLET_NONE           \
    + SSS_HAVE_APPLET_A71CH          \
    + SSS_HAVE_APPLET_A71CL          \
    + SSS_HAVE_APPLET_A71CH_SIM      \
    + SSS_HAVE_APPLET_SE05X_A        \
    + SSS_HAVE_APPLET_SE05X_B        \
    + SSS_HAVE_APPLET_SE05X_C        \
    + SSS_HAVE_APPLET_SE05X_L        \
    + SSS_HAVE_APPLET_LOOPBACK       \
    ) == 0)
#        error "Enable at-least one of 'Applet'"
#endif



/** SE05X_Ver : SE50 Applet version.
 *
 * 03_XX would only enable features of version 03.XX version of applet.
 * But, this would be compatibility would be added for newer versions of the Applet.
 * When 04_XX is selected, it would expose features available in 04_XX at compile time.
 */

/** SE050 */
#define SSS_HAVE_SE05X_VER_03_XX 1

/** NXP Internal - 4.4 */
#define SSS_HAVE_SE05X_VER_04_04 0

/** NXP Internal - 5.00 */
#define SSS_HAVE_SE05X_VER_05_00 0

/** NXP Internal - 5.02 */
#define SSS_HAVE_SE05X_VER_05_02 0

/** NXP Internal - 5.04 */
#define SSS_HAVE_SE05X_VER_05_04 0

/** NXP Internal - 5.06 */
#define SSS_HAVE_SE05X_VER_05_06 0

/** NXP Internal - 5.08 */
#define SSS_HAVE_SE05X_VER_05_08 0

/** NXP Internal - 5.10 */
#define SSS_HAVE_SE05X_VER_05_10 0

/** NXP Internal - 5.12 */
#define SSS_HAVE_SE05X_VER_05_12 0

#if (( 0                             \
    + SSS_HAVE_SE05X_VER_03_XX       \
    + SSS_HAVE_SE05X_VER_04_04       \
    + SSS_HAVE_SE05X_VER_05_00       \
    + SSS_HAVE_SE05X_VER_05_02       \
    + SSS_HAVE_SE05X_VER_05_04       \
    + SSS_HAVE_SE05X_VER_05_06       \
    + SSS_HAVE_SE05X_VER_05_08       \
    + SSS_HAVE_SE05X_VER_05_10       \
    + SSS_HAVE_SE05X_VER_05_12       \
    ) > 1)
#        error "Enable only one of 'SE05X_Ver'"
#endif


#if (( 0                             \
    + SSS_HAVE_SE05X_VER_03_XX       \
    + SSS_HAVE_SE05X_VER_04_04       \
    + SSS_HAVE_SE05X_VER_05_00       \
    + SSS_HAVE_SE05X_VER_05_02       \
    + SSS_HAVE_SE05X_VER_05_04       \
    + SSS_HAVE_SE05X_VER_05_06       \
    + SSS_HAVE_SE05X_VER_05_08       \
    + SSS_HAVE_SE05X_VER_05_10       \
    + SSS_HAVE_SE05X_VER_05_12       \
    ) == 0)
#        error "Enable at-least one of 'SE05X_Ver'"
#endif



/** HostCrypto : Counterpart Crypto on Host
 *
 * What is being used as a cryptographic library on the host.
 * As of now only OpenSSL / mbedTLS is supported
 */

/** Use mbedTLS as host crypto */
#define SSS_HAVE_HOSTCRYPTO_MBEDTLS 0

/** Use mbed-crypto as host crypto
 * Required for ARM-PSA / TF-M
 * NXP Internal
 */
#define SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO 0

/** Use OpenSSL as host crypto */
#define SSS_HAVE_HOSTCRYPTO_OPENSSL 0

/** User Implementation of Host Crypto
 * e.g. Files at ``sss/src/user/crypto`` have low level AES/CMAC primitives.
 * The files at ``sss/src/user`` use those primitives.
 * This becomes an example for users with their own AES Implementation
 * This then becomes integration without mbedTLS/OpenSSL for SCP03 / AESKey.
 *
 * .. note:: ECKey abstraction is not implemented/available yet. */
#define SSS_HAVE_HOSTCRYPTO_USER 0

/** NO Host Crypto
 * Note, this is unsecure and only provided for experimentation
 * on platforms that do not have an mbedTLS PORT
 * Many :ref:`sssftr-control` have to be disabled to have a valid build. */
#define SSS_HAVE_HOSTCRYPTO_NONE 0

#if (( 0                             \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_USER       \
    + SSS_HAVE_HOSTCRYPTO_NONE       \
    ) > 1)
#        error "Enable only one of 'HostCrypto'"
#endif


/** mbedTLS_ALT : ALT Engine implementation for mbedTLS
 *
 * When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Element.
 * This needs to be set to SSS for Cloud Demos over SSS APIs
 */

/** Use SSS Layer ALT implementation */
#define SSS_HAVE_MBEDTLS_ALT_SSS 1

/** Legacy implementation */
#define SSS_HAVE_MBEDTLS_ALT_A71CH 0

/** Not using any mbedTLS_ALT
 *
 * When this is selected, cloud demos can not work with mbedTLS */
#define SSS_HAVE_MBEDTLS_ALT_NONE 0

#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_A71CH     \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) > 1)
#        error "Enable only one of 'mbedTLS_ALT'"
#endif


#if (( 0                             \
    + SSS_HAVE_MBEDTLS_ALT_SSS       \
    + SSS_HAVE_MBEDTLS_ALT_A71CH     \
    + SSS_HAVE_MBEDTLS_ALT_NONE      \
    ) == 0)
#        error "Enable at-least one of 'mbedTLS_ALT'"
#endif



/** SCP : Secure Channel Protocol
 *
 * In case we enable secure channel to Secure Element, which interface to be used.
 */

/**  */
#define SSS_HAVE_SCP_NONE 0

/** Use SSS Layer for SCP.  Used for SE050 family. */
#define SSS_HAVE_SCP_SCP03_SSS 0

/** Use Host Crypto Layer for SCP03. Legacy implementation. Used for older demos of A71CH Family. */
#define SSS_HAVE_SCP_SCP03_HOSTCRYPTO 0

#if (( 0                             \
    + SSS_HAVE_SCP_NONE              \
    + SSS_HAVE_SCP_SCP03_SSS         \
    + SSS_HAVE_SCP_SCP03_HOSTCRYPTO  \
    ) > 1)
#        error "Enable only one of 'SCP'"
#endif


/** FIPS : Enable or disable FIPS
 *
 * This selection mostly impacts tests, and generally not the actual Middleware
 */

/** NO FIPS */
#define SSS_HAVE_FIPS_NONE 1

/** SE050 IC FIPS */
#define SSS_HAVE_FIPS_SE050 0

/** FIPS 140-2 */
#define SSS_HAVE_FIPS_140_2 0

/** FIPS 140-3 */
#define SSS_HAVE_FIPS_140_3 0

#if (( 0                             \
    + SSS_HAVE_FIPS_NONE             \
    + SSS_HAVE_FIPS_SE050            \
    + SSS_HAVE_FIPS_140_2            \
    + SSS_HAVE_FIPS_140_3            \
    ) > 1)
#        error "Enable only one of 'FIPS'"
#endif


#if (( 0                             \
    + SSS_HAVE_FIPS_NONE             \
    + SSS_HAVE_FIPS_SE050            \
    + SSS_HAVE_FIPS_140_2            \
    + SSS_HAVE_FIPS_140_3            \
    ) == 0)
#        error "Enable at-least one of 'FIPS'"
#endif



/** SE05X_Auth : SE050 Authentication
 *
 * This settings is used by examples to connect using various options
 * to authenticate with the Applet.
 * The SE05X_Auth options can be changed for KSDK Demos and Examples.
 * To change SE05X_Auth option follow below steps.
 * Set flag ``SSS_HAVE_SCP_SCP03_SSS`` to 1 and Reset flag ``SSS_HAVE_SCP_NONE`` to 0.
 * To change SE05X_Auth option other than ``None`` and  ``PlatfSCP03``,
 * execute se05x_Delete_and_test_provision.exe in order to provision the Authentication Key.
 * To change SE05X_Auth option to ``ECKey`` or ``ECKey_PlatfSCP03``,
 * Set additional flag ``SSS_HAVE_HOSTCRYPTO_ANY`` to 1.
 */

/** Use the default session (i.e. session less) login */
#define SSS_HAVE_SE05X_AUTH_NONE 1

/** Do User Authentication with UserID */
#define SSS_HAVE_SE05X_AUTH_USERID 0

/** Use Platform SCP for connection to SE */
#define SSS_HAVE_SE05X_AUTH_PLATFSCP03 0

/** Do User Authentication with AES Key
 * Earlier this was called AppletSCP03 */
#define SSS_HAVE_SE05X_AUTH_AESKEY 0

/** Do User Authentication with EC Key
 * Earlier this was called FastSCP */
#define SSS_HAVE_SE05X_AUTH_ECKEY 0

/** UserID and PlatfSCP03 */
#define SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 0

/** AESKey and PlatfSCP03 */
#define SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 0

/** ECKey and PlatfSCP03 */
#define SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 0

#if (( 0                             \
    + SSS_HAVE_SE05X_AUTH_NONE       \
    + SSS_HAVE_SE05X_AUTH_USERID     \
    + SSS_HAVE_SE05X_AUTH_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_AESKEY     \
    + SSS_HAVE_SE05X_AUTH_ECKEY      \
    + SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 \
    ) > 1)
#        error "Enable only one of 'SE05X_Auth'"
#endif


#if (( 0                             \
    + SSS_HAVE_SE05X_AUTH_NONE       \
    + SSS_HAVE_SE05X_AUTH_USERID     \
    + SSS_HAVE_SE05X_AUTH_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_AESKEY     \
    + SSS_HAVE_SE05X_AUTH_ECKEY      \
    + SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03 \
    + SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03 \
    ) == 0)
#        error "Enable at-least one of 'SE05X_Auth'"
#endif



/** A71CH_AUTH : A71CH Authentication
 *
 * This settings is used by SSS-API based examples to connect using either plain or authenticated to the A71CH.
 */

/** Plain communication, not authenticated or encrypted */
#define SSS_HAVE_A71CH_AUTH_NONE 1

/** SCP03 enabled */
#define SSS_HAVE_A71CH_AUTH_SCP03 0

#if (( 0                             \
    + SSS_HAVE_A71CH_AUTH_NONE       \
    + SSS_HAVE_A71CH_AUTH_SCP03      \
    ) > 1)
#        error "Enable only one of 'A71CH_AUTH'"
#endif


#if (( 0                             \
    + SSS_HAVE_A71CH_AUTH_NONE       \
    + SSS_HAVE_A71CH_AUTH_SCP03      \
    ) == 0)
#        error "Enable at-least one of 'A71CH_AUTH'"
#endif


/* ====================================================================== *
 * == Feature selection/values ========================================== *
 * ====================================================================== */


/** SE05X Secure Element : Symmetric AES */
#define SSSFTR_SE05X_AES 1

/** SE05X Secure Element : Elliptic Curve Cryptography */
#define SSSFTR_SE05X_ECC 1

/** SE05X Secure Element : RSA */
#define SSSFTR_SE05X_RSA 1

/** SE05X Secure Element : KEY operations : SET Key */
#define SSSFTR_SE05X_KEY_SET 1

/** SE05X Secure Element : KEY operations : GET Key */
#define SSSFTR_SE05X_KEY_GET 1

/** SE05X Secure Element : Authenticate via ECKey */
#define SSSFTR_SE05X_AuthECKey 1

/** SE05X Secure Element : Allow creation of user/authenticated session.
 *
 * If the intended deployment only uses Platform SCP
 * Or it is a pure session less integration, this can
 * save some code size. */
#define SSSFTR_SE05X_AuthSession 0

/** SE05X Secure Element : Allow creation/deletion of Crypto Objects
 *
 * If disabled, new Crytpo Objects are neither created and
 * old/existing Crypto Objects are not deleted.
 * It is assumed that during provisioning phase, the required
 * Crypto Objects are pre-created or they are never going to
 * be needed. */
#define SSSFTR_SE05X_CREATE_DELETE_CRYPTOOBJ 1

/** Software : Symmetric AES */
#define SSSFTR_SW_AES 1

/** Software : Elliptic Curve Cryptography */
#define SSSFTR_SW_ECC 1

/** Software : RSA */
#define SSSFTR_SW_RSA 1

/** Software : KEY operations : SET Key */
#define SSSFTR_SW_KEY_SET 1

/** Software : KEY operations : GET Key */
#define SSSFTR_SW_KEY_GET 1

/** Software : Used as a test counterpart
 *
 * e.g. Major part of the mebdTLS SSS layer is purely used for
 * testing of Secure Element implementation, and can be avoided
 * fully during many production scenarios. */
#define SSSFTR_SW_TESTCOUNTERPART 1

/* ====================================================================== *
 * == Computed Options ================================================== *
 * ====================================================================== */

/** Symmetric AES */
#define SSSFTR_AES               (SSSFTR_SE05X_AES + SSSFTR_SW_AES)
/** Elliptic Curve Cryptography */
#define SSSFTR_ECC               (SSSFTR_SE05X_ECC + SSSFTR_SW_ECC)
/** RSA */
#define SSSFTR_RSA               (SSSFTR_SE05X_RSA + SSSFTR_SW_RSA)
/** KEY operations : SET Key */
#define SSSFTR_KEY_SET           (SSSFTR_SE05X_KEY_SET + SSSFTR_SW_KEY_SET)
/** KEY operations : GET Key */
#define SSSFTR_KEY_GET           (SSSFTR_SE05X_KEY_GET + SSSFTR_SW_KEY_GET)
/** KEY operations */
#define SSSFTR_KEY               (SSSFTR_KEY_SET + SSSFTR_KEY_GET)
/** KEY operations */
#define SSSFTR_SE05X_KEY         (SSSFTR_SE05X_KEY_SET + SSSFTR_SE05X_KEY_GET)
/** KEY operations */
#define SSSFTR_SW_KEY            (SSSFTR_SW_KEY_SET + SSSFTR_SW_KEY_GET)


#define SSS_HAVE_APPLET \
 (SSS_HAVE_APPLET_A71CH | SSS_HAVE_APPLET_A71CL | SSS_HAVE_APPLET_A71CH_SIM | SSS_HAVE_APPLET_SE05X_A | SSS_HAVE_APPLET_SE05X_B | SSS_HAVE_APPLET_SE05X_C | SSS_HAVE_APPLET_SE05X_L | SSS_HAVE_APPLET_LOOPBACK)

#define SSS_HAVE_APPLET_SE05X_IOT \
 (SSS_HAVE_APPLET_SE05X_A | SSS_HAVE_APPLET_SE05X_B | SSS_HAVE_APPLET_SE05X_C)

#define SSS_HAVE_MBEDTLS_ALT \
 (SSS_HAVE_MBEDTLS_ALT_SSS | SSS_HAVE_MBEDTLS_ALT_A71CH)

#define SSS_HAVE_HOSTCRYPTO_ANY \
 (SSS_HAVE_HOSTCRYPTO_MBEDTLS | SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO | SSS_HAVE_HOSTCRYPTO_OPENSSL | SSS_HAVE_HOSTCRYPTO_USER)

#define SSS_HAVE_FIPS \
 (SSS_HAVE_FIPS_SE050 | SSS_HAVE_FIPS_140_2 | SSS_HAVE_FIPS_140_3)


/* Version checks GTE - Greater Than Or Equal To */
#if SSS_HAVE_APPLET_SE05X_IOT
#    if SSS_HAVE_SE05X_VER_05_12
#        define SSS_HAVE_SE05X_VER_GTE_05_12 1
#        define SSS_HAVE_SE05X_VER_GTE_05_10 1
#        define SSS_HAVE_SE05X_VER_GTE_05_08 1
#        define SSS_HAVE_SE05X_VER_GTE_05_06 1
#        define SSS_HAVE_SE05X_VER_GTE_05_04 1
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_12 */
#    if SSS_HAVE_SE05X_VER_05_10
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 1
#        define SSS_HAVE_SE05X_VER_GTE_05_08 1
#        define SSS_HAVE_SE05X_VER_GTE_05_06 1
#        define SSS_HAVE_SE05X_VER_GTE_05_04 1
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_10 */
#    if SSS_HAVE_SE05X_VER_05_08
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 1
#        define SSS_HAVE_SE05X_VER_GTE_05_06 1
#        define SSS_HAVE_SE05X_VER_GTE_05_04 1
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_08 */
#    if SSS_HAVE_SE05X_VER_05_06
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 1
#        define SSS_HAVE_SE05X_VER_GTE_05_04 1
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_06 */
#    if SSS_HAVE_SE05X_VER_05_04
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 1
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_04 */
#    if SSS_HAVE_SE05X_VER_05_02
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 1
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_02 */
#    if SSS_HAVE_SE05X_VER_05_00
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 0
#        define SSS_HAVE_SE05X_VER_GTE_05_00 1
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_05_00 */
#    if SSS_HAVE_SE05X_VER_04_12
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 0
#        define SSS_HAVE_SE05X_VER_GTE_05_00 0
#        define SSS_HAVE_SE05X_VER_GTE_04_12 1
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_04_12 */
#    if SSS_HAVE_SE05X_VER_04_08
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 0
#        define SSS_HAVE_SE05X_VER_GTE_05_00 0
#        define SSS_HAVE_SE05X_VER_GTE_04_12 0
#        define SSS_HAVE_SE05X_VER_GTE_04_08 1
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_04_08 */
#    if SSS_HAVE_SE05X_VER_04_04
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 0
#        define SSS_HAVE_SE05X_VER_GTE_05_00 0
#        define SSS_HAVE_SE05X_VER_GTE_04_12 0
#        define SSS_HAVE_SE05X_VER_GTE_04_08 0
#        define SSS_HAVE_SE05X_VER_GTE_04_04 1
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_04_04 */
#    if SSS_HAVE_SE05X_VER_03_XX
#        define SSS_HAVE_SE05X_VER_GTE_05_12 0
#        define SSS_HAVE_SE05X_VER_GTE_05_10 0
#        define SSS_HAVE_SE05X_VER_GTE_05_08 0
#        define SSS_HAVE_SE05X_VER_GTE_05_06 0
#        define SSS_HAVE_SE05X_VER_GTE_05_04 0
#        define SSS_HAVE_SE05X_VER_GTE_05_02 0
#        define SSS_HAVE_SE05X_VER_GTE_05_00 0
#        define SSS_HAVE_SE05X_VER_GTE_04_12 0
#        define SSS_HAVE_SE05X_VER_GTE_04_08 0
#        define SSS_HAVE_SE05X_VER_GTE_04_04 0
#        define SSS_HAVE_SE05X_VER_GTE_03_XX 1
#    endif /* SSS_HAVE_SE05X_VER_03_XX */
#else //SSS_HAVE_APPLET_SE05X_IOT
#   define SSS_HAVE_SE05X_VER_GTE_03_XX 0
#   define SSS_HAVE_SE05X_VER_GTE_04_04 0
#   define SSS_HAVE_SE05X_VER_GTE_04_08 0
#   define SSS_HAVE_SE05X_VER_GTE_04_12 0
#   define SSS_HAVE_SE05X_VER_GTE_05_00 0
#   define SSS_HAVE_SE05X_VER_GTE_05_02 0
#   define SSS_HAVE_SE05X_VER_GTE_05_04 0
#   define SSS_HAVE_SE05X_VER_GTE_05_06 0
#   define SSS_HAVE_SE05X_VER_GTE_05_08 0
#   define SSS_HAVE_SE05X_VER_GTE_05_10 0
#   define SSS_HAVE_SE05X_VER_GTE_05_12 0
#endif // SSS_HAVE_APPLET_SE05X_IOT
/** Deprecated items. Used here for backwards compatibility. */

#define WithApplet_SE05X (SSS_HAVE_APPLET_SE05X_IOT)
#define WithApplet_SE050_A (SSS_HAVE_APPLET_SE05X_A)
#define WithApplet_SE050_B (SSS_HAVE_APPLET_SE05X_B)
#define WithApplet_SE050_C (SSS_HAVE_APPLET_SE05X_C)
#define SSS_HAVE_SE050_A (SSS_HAVE_APPLET_SE05X_A)
#define SSS_HAVE_SE050_B (SSS_HAVE_APPLET_SE05X_B)
#define SSS_HAVE_SE050_C (SSS_HAVE_APPLET_SE05X_C)
#define SSS_HAVE_SE05X (SSS_HAVE_APPLET_SE05X_IOT)
#define SSS_HAVE_SE (SSS_HAVE_APPLET)
#define SSS_HAVE_LOOPBACK (SSS_HAVE_APPLET_LOOPBACK)
#define SSS_HAVE_ALT (SSS_HAVE_MBEDTLS_ALT)
#define WithApplet_None (SSS_HAVE_APPLET_NONE)
#define SSS_HAVE_None (SSS_HAVE_APPLET_NONE)
#define WithApplet_A71CH (SSS_HAVE_APPLET_A71CH)
#define SSS_HAVE_A71CH (SSS_HAVE_APPLET_A71CH)
#define WithApplet_A71CL (SSS_HAVE_APPLET_A71CL)
#define SSS_HAVE_A71CL (SSS_HAVE_APPLET_A71CL)
#define WithApplet_A71CH_SIM (SSS_HAVE_APPLET_A71CH_SIM)
#define SSS_HAVE_A71CH_SIM (SSS_HAVE_APPLET_A71CH_SIM)
#define WithApplet_SE05X_A (SSS_HAVE_APPLET_SE05X_A)
#define SSS_HAVE_SE05X_A (SSS_HAVE_APPLET_SE05X_A)
#define WithApplet_SE05X_B (SSS_HAVE_APPLET_SE05X_B)
#define SSS_HAVE_SE05X_B (SSS_HAVE_APPLET_SE05X_B)
#define WithApplet_SE05X_C (SSS_HAVE_APPLET_SE05X_C)
#define SSS_HAVE_SE05X_C (SSS_HAVE_APPLET_SE05X_C)
#define WithApplet_SE05X_L (SSS_HAVE_APPLET_SE05X_L)
#define SSS_HAVE_SE05X_L (SSS_HAVE_APPLET_SE05X_L)
#define WithApplet_LoopBack (SSS_HAVE_APPLET_LOOPBACK)
#define SSS_HAVE_LoopBack (SSS_HAVE_APPLET_LOOPBACK)
#define SSS_HAVE_MBEDTLS (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
#define SSS_HAVE_MBEDCRYPTO (SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO)
#define SSS_HAVE_OPENSSL (SSS_HAVE_HOSTCRYPTO_OPENSSL)
#define SSS_HAVE_USER (SSS_HAVE_HOSTCRYPTO_USER)
#define SSS_HAVE_NONE (SSS_HAVE_HOSTCRYPTO_NONE)
#define SSS_HAVE_ALT_SSS (SSS_HAVE_MBEDTLS_ALT_SSS)
#define SSS_HAVE_ALT_A71CH (SSS_HAVE_MBEDTLS_ALT_A71CH)
#define SSS_HAVE_ALT_NONE (SSS_HAVE_MBEDTLS_ALT_NONE)
#define SSS_HAVE_SE05X_Auth_None (SSS_HAVE_SE05X_AUTH_NONE)
#define SSS_HAVE_SE05X_Auth_UserID (SSS_HAVE_SE05X_AUTH_USERID)
#define SSS_HAVE_SE05X_Auth_PlatfSCP03 (SSS_HAVE_SE05X_AUTH_PLATFSCP03)
#define SSS_HAVE_SE05X_Auth_AESKey (SSS_HAVE_SE05X_AUTH_AESKEY)
#define SSS_HAVE_SE05X_Auth_ECKey (SSS_HAVE_SE05X_AUTH_ECKEY)
#define SSS_HAVE_SE05X_Auth_UserID_PlatfSCP03 (SSS_HAVE_SE05X_AUTH_USERID_PLATFSCP03)
#define SSS_HAVE_SE05X_Auth_AESKey_PlatfSCP03 (SSS_HAVE_SE05X_AUTH_AESKEY_PLATFSCP03)
#define SSS_HAVE_SE05X_Auth_ECKey_PlatfSCP03 (SSS_HAVE_SE05X_AUTH_ECKEY_PLATFSCP03)

/* # CMake Features : END */

/* ========= Miscellaneous values : START =================== */

/* ECC Mode is available */
#define SSS_HAVE_ECC 1

/* RSA is available */
#define SSS_HAVE_RSA 1

/* TPM BARRETO_NAEHRIG Curve is enabled */
#define SSS_HAVE_TPM_BN 1

/* Edwards Curve is enabled */
#define SSS_HAVE_EC_ED 1

/* Montgomery Curve is enabled */
#define SSS_HAVE_EC_MONT 1

/* TLS handshake support on SE is enabled */
#define SSS_HAVE_TLS_HANDSHAKE 1

/* Import Export Key is enabled */
#define SSS_HAVE_IMPORT 1

/* With NXP NFC Reader Library */
#define SSS_HAVE_NXPNFCRDLIB 0

#define SSS_HAVE_A71XX \
    (SSS_HAVE_APPLET_A71CH | SSS_HAVE_APPLET_A71CH_SIM)

#define SSS_HAVE_SSCP  (SSS_HAVE_A71XX)

/* For backwards compatibility */
#define SSS_HAVE_TESTCOUNTERPART (SSSFTR_SW_TESTCOUNTERPART)

/* ========= Miscellaneous values : END ===================== */

/* ========= Calculated values : START ====================== */

/* Should we expose, SSS APIs */
#define SSS_HAVE_SSS ( 0             \
    + SSS_HAVE_SSCP                  \
    + SSS_HAVE_APPLET_SE05X_IOT      \
    + SSS_HAVE_HOSTCRYPTO_OPENSSL    \
    + SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO \
    + SSS_HAVE_HOSTCRYPTO_MBEDTLS    \
    + SSS_HAVE_HOSTCRYPTO_USER       \
    )

/* MBEDCRYPTO is superset of MBEDTLS and exposing that way */
#if SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO
#   undef SSS_HAVE_MBEDTLS
#   undef SSS_HAVE_HOSTCRYPTO_MBEDTLS

#   define SSS_HAVE_MBEDTLS 1
#   define SSS_HAVE_HOSTCRYPTO_MBEDTLS 1
#endif // SSS_HAVE_HOSTCRYPTO_MBEDCRYPTO

#if SSS_HAVE_HOSTCRYPTO_NONE
#   undef SSSFTR_SE05X_AuthSession
#   define SSSFTR_SE05X_AuthSession 0
#endif

#if SSS_HAVE_APPLET_SE05X_A
#   undef SSS_HAVE_EC_MONT
#   define SSS_HAVE_EC_MONT 0
#endif

/* ========= Calculated values : END ======================== */

/* clang-format on */

#endif /* SSS_APIS_INC_FSL_SSS_FTR_H_ */
