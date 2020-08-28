/*
* Copyright 2018,2020 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NXSCP03_TYPES_H_
#define NXSCP03_TYPES_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <fsl_sss_api.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif
#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_apis.h>
#endif
#if SSS_HAVE_HOSTCRYPTO_USER
#   include <fsl_sss_user_apis.h>
#endif

#include "sm_api.h"
#if SSS_HAVE_SSCP
#include "fsl_sscp_a71ch.h"
#endif

typedef enum
{
    kSSS_AuthType_None = 0,
    /** Global platform SCP03 */
    kSSS_AuthType_SCP03 = 1,
    /** (e.g. SE05X) UserID based connection */
    kSSS_AuthType_ID = 2,

    /** (e.g. SE05X) Use AESKey for user authentication
     *
     *  Earlier this was called  kSSS_AuthType_AppletSCP03
     */
    kSSS_AuthType_AESKey = 3,
    /** (e.g. SE05X) Use ECKey for user authentication
     *
     *  Earlier this was called  kSSS_AuthType_FastSCP
     */
    kSSS_AuthType_ECKey = 4,

    /* ================ Internal ======================= */
    /* Not to be selected by end user... directly */

    /**
     * Used internally, not to be set/used by user.
     *
     * For the versions of the applet where we have to add
     * the a counter during KDF.
     */
    kSSS_AuthType_INT_ECKey_Counter = 0x14,

    kSSS_SIZE = 0x7FFFFFFF,
} SE_AuthType_t;

#define kSSS_AuthType_INT_FastSCP_Counter kSSS_AuthType_INT_ECKey_Counter
#define kSSS_AuthType_FastSCP_Counter kSSS_AuthType_INT_ECKey_Counter
#define kSSS_AuthType_FastSCP         kSSS_AuthType_ECKey
#define kSSS_AuthType_AppletSCP03     kSSS_AuthType_AESKey

/**
 * Dynamic SCP03 Context.
 *
 * This structure is filled **after** establishing
 * an SCP03 session.
 */
typedef struct
{
    sss_object_t Enc;  //!< session channel encryption key
    sss_object_t Mac;  //!< session command authentication key
    sss_object_t Rmac; //!< session response authentication key
    uint8_t MCV[16];        //!<  MAC chaining value
    uint8_t cCounter[16];   //!<  command counter
    uint8_t SecurityLevel;  //!< security level set

    /** Handle differnt types of auth.. PlatformSCP / AppletSCP */
    SE_AuthType_t authType;
} NXSCP03_DynCtx_t;

/**
 * Static SCP03 Context.
 *
 * This structure is filled **before** establishing
 * an SCP03 session.
 *
 * Depending on system, these objects may point to keys
 * inside other security system.
 */
typedef struct
{
    /** Key version no to use for chanel
        authentication in SCP03     */
    uint8_t keyVerNo;
    /** Encryption key object */
    sss_object_t Enc;
    sss_object_t Mac; //!< static secure channel authentication key obj
    sss_object_t Dek; //!< data encryption key obj
} NXSCP03_StaticCtx_t;

/**
* Static and  Dynamic Context in one Context.
*
*
* Depending on system, these objects may point to keys
* inside other security system.
*/
typedef struct
{
    NXSCP03_StaticCtx_t *pStatic_ctx; //!< .static keys data
    NXSCP03_DynCtx_t *pDyn_ctx;       //!<  session keys data
} NXSCP03_AuthCtx_t;

/** Static part of keys for FAST SCP */
typedef struct
{
    /** Host ECDSA Private key */
    sss_object_t HostEcdsaObj;
    /** Host ephemeral ECC key pair */
    sss_object_t HostEcKeypair;
    /** SE ECC public key */
    sss_object_t SeEcPubKey;
    /** Host master Secret */
    sss_object_t masterSec;
} NXECKey03_StaticCtx_t;

/** Keys to connect for a ECKey Connection */
typedef struct
{
    /** The Input/Static part of the ECKey Authentication
     *
     * We start/initiate a session with the keys here.
     */
    NXECKey03_StaticCtx_t *pStatic_ctx;
    /** The Dynamic part of the ECKey Authentication
     *
     * We derive/compute the session keys based on the
     * ``pStatic_ctx``.
     */
    NXSCP03_DynCtx_t  *pDyn_ctx;   // session keys data
} SE05x_AuthCtx_ECKey_t;

/** UseID / PIN baed authentication object
 *
 * This is required to open an UserID / PIN based session to the SE.
 */
typedef struct
{
    /** The corresponding authentication object on the Host */
    sss_object_t * pObj;
} SE05x_AuthCtx_ID_t;


/** Legacy, only for A71CH with Host Crypto */
typedef struct
{
    sss_object_t pKeyEnc; //!< SSS AES Enc Key object
    sss_object_t pKeyMac; //!< SSS AES Mac Key object
    sss_object_t pKeyDek; //!< SSS AES Dek Key object
} SM_SECURE_SCP03_KEYOBJ;

/** Authentication mechanims */
typedef struct _SE_AuthCtx
{
    /** How exactly we are going to authenticat ot the system.
     *
     * Since ``ctx`` is a union, this is needed to know exactly how
     * we are going to authenticate.
     */

    SE_AuthType_t authType;

    /** Depending on ``authType``, the input and output parameters.
     *
     * This has both input and output parameters.
     *
     * Input is for Keys that are used to initiate the connection.
     * While connecting, session keys/parameters are generated and they
     * are also part of this context.
     *
     * In any case, we connect to only one type
     */
    union {
        /** For PlatformSCP / Applet SCP.
         *
         * Same SCP context will be used for platform and applet scp03 */
        NXSCP03_AuthCtx_t scp03;

        /** For ECKey  */
        SE05x_AuthCtx_ECKey_t eckey;

        /** For UserID/PIN based based Authentication */
        SE05x_AuthCtx_ID_t idobj;

        /** Legacy, only for A71CH with Host Crypto */
        SM_SECURE_SCP03_KEYOBJ a71chAuthKeys;

        /** Reserved memory for implementation specific extension */
        struct
        {
            uint8_t data[SSS_AUTH_MAX_CONTEXT_SIZE];
        } extension;
    } ctx;
} SE_AuthCtx_t;

/**
 * When connecting to a secure element,
 *
 * Extension of sss_connect_ctx_t
 */
typedef struct
{
    /** to support binary compatibility/check, sizeOfStucture helps */
    uint16_t sizeOfStucture;
    /** If we need to authenticate, add required objects for authentication */
    SE_AuthCtx_t auth;
    /** If some policy restrictions apply when we connect, point it here */
    sss_policy_session_u *session_policy;

    /* =================================== */
    /* Implementation specific part starts */
    /* =================================== */

    /** If we connect logically, via some software layer */
    sss_tunnel_t *tunnelCtx;

    /** How exactly are we going to connect physically */
    SSS_Conn_Type_t connType;

    /** Connection port name for Socket names, etc. */
    const char *portName;

    /** 12C address on embedded devices. */
    U32 i2cAddress;

    /** If we need to refresh session, SE050 specific */
    uint8_t refresh_session : 1;

    /** In the case of Key Rotation, and other use cases
     * where we do not select the IoT Applet and skip
     * the selection of the IoT Applet.
     *
     * One of the use cases is to do platform SCP
     * key rotation.
     *
     * When set to 0:
     *  Do not skip IoT Applet selection and run as-is.
     *
     * When set to 1:
     *  Skip selection of card manager.
     *  Skip selection of Applet.
     *
     * Internally, if there is platform SCP selected as
     * Auth mechanism during compile time, the internal
     * logic would Select the card manager. But,
     * skip selection of the Applet.
     *
     */
    uint8_t skip_select_applet : 1;
} SE_Connect_Ctx_t;

/** Wrapper strucutre sss_connect_ctx_t */
typedef struct
{
    /** To support binary compatibility/check, sizeOfStucture helps */
    uint16_t sizeOfStucture;
    /** If we need to authenticate, add required objects for authentication */
    SE_AuthCtx_t auth;
    /** If some policy restrictions apply when we connect, point it here */
    sss_policy_session_u *session_policy;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_CONNECT_MAX_CONTEXT_SIZE];
    } extension;
} sss_connect_ctx_t;

/* Deprecated */

#define SE05x_AuthCtx_t SE_AuthCtx_t

#define kSE05x_AuthType_None kSSS_AuthType_None
#define kSE05x_AuthType_SCP03 kSSS_AuthType_SCP03
#define kSE05x_AuthType_UserID kSSS_AuthType_ID
#define kSE05x_AuthType_AESKey kSSS_AuthType_AESKey
#define kSE05x_AuthType_ECKey kSSS_AuthType_ECKey

/* For backwards compatibility */
#define SE05x_AuthType_t SE_AuthType_t

#endif /* NXSCP03_TYPES_H_ */
