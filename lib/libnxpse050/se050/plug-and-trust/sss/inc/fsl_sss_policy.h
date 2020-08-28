/*
 * Copyright 2019,2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** @file */

#ifndef _FSL_SSS_POLICY_H_
#define _FSL_SSS_POLICY_H_

#if !defined(SSS_CONFIG_FILE)
#include "fsl_sss_config.h"
#else
#include SSS_CONFIG_FILE
#endif

#include "fsl_sss_types.h"
//#include <Applet_SE050_Ver.h>

/** @defgroup sss_policy Policy
 *
 * Policies to restrict and control sessions and objects.
 */

/** @addtogroup sss_policy
 * @{ */

/** Type of policy */
typedef enum
{
    /** No policy applied */
    KPolicy_None,
    /** Policy related to session.  @see sss_policy_session_u */
    KPolicy_Session,
    /** Policy related to key.  @see sss_policy_key_u */
    KPolicy_Sym_Key,
    KPolicy_Asym_Key,
    KPolicy_UserID,
    KPolicy_File,
    KPolicy_Counter,
    KPolicy_PCR,
    KPolicy_Common,
    KPolicy_Common_PCR_Value,
} sss_policy_type_u;

/** Policy applicable to a session */
typedef struct
{
    /** Number of operations permitted in a session */
    uint16_t maxOperationsInSession;
    /** Session can be used for this much time, in seconds */
    uint16_t maxDurationOfSession_sec;
    /** Whether maxOperationsInSession is set.
     * This is to ensure '0 == maxOperationsInSession' does not get set
     * by middleware. */
    uint8_t has_MaxOperationsInSession : 1;
    /** Whether maxOperationsInSession is set.
     * This is to ensure '0 == maxDurationOfSession_sec' does not get set
     * by middleware. */
    uint8_t has_MaxDurationOfSession_sec : 1;
    /** Whether this session can be refreshed without losing context.
     * And also reset maxDurationOfSession_sec / maxOperationsInSession */
    uint8_t allowRefresh : 1;
} sss_policy_session_u;

/** Policies applicable to Symmetric KEY */
typedef struct
{
    /** Allow signature generation */
    uint8_t can_Sign : 1;
    /** Allow signature verification */
    uint8_t can_Verify : 1;
    /** Allow encryption */
    uint8_t can_Encrypt : 1;
    /** Allow decryption */
    uint8_t can_Decrypt : 1;
    /** Allow key derivation */
    uint8_t can_KD : 1;
    /** Allow key wrapping */
    uint8_t can_Wrap : 1;
    /** Allow to write the object */
    uint8_t can_Write : 1;
    /** Allow to (re)generate the object */
    uint8_t can_Gen : 1;
    /** Allow to perform DESFire authentication */
    uint8_t can_Desfire_Auth : 1;
    /** Allow to dump DESFire session keys */
    uint8_t can_Desfire_Dump : 1;
    /** Allow to imported or exported */
    uint8_t can_Import_Export : 1;
#if 1 // SSS_HAVE_SE05X_VER_GTE_04_04
    /** Forbid derived output */
    uint8_t forbid_Derived_Output : 1;
#endif
    /** Allow kdf(prf) external random */
    uint8_t allow_kdf_ext_rnd : 1;
} sss_policy_sym_key_u;

/** Policies applicable to Asymmetric KEY */
typedef struct
{
    /** Allow signature generation */
    uint8_t can_Sign : 1;
    /** Allow signature verification */
    uint8_t can_Verify : 1;
    /** Allow encryption */
    uint8_t can_Encrypt : 1;
    /** Allow decryption */
    uint8_t can_Decrypt : 1;
    /** Allow key derivation */
    uint8_t can_KD : 1;
    /** Allow key wrapping */
    uint8_t can_Wrap : 1;
    /** Allow to write the object */
    uint8_t can_Write : 1;
    /** Allow to (re)generate the object */
    uint8_t can_Gen : 1;
    /** Allow to imported or exported */
    uint8_t can_Import_Export : 1;
    /** Allow key agreement */
    uint8_t can_KA : 1;
    /** Allow to read the object */
    uint8_t can_Read : 1;
    /** Allow to attest an object */
    uint8_t can_Attest : 1;
#if 1 // SSS_HAVE_SE05X_VER_GTE_04_04
    /** Forbid derived output */
    uint8_t forbid_Derived_Output : 1;
#endif
} sss_policy_asym_key_u;

/** All policies related to secure object type File */
typedef struct
{
    /** Allow to write the object */
    uint8_t can_Write : 1;
    /** Allow to read the object */
    uint8_t can_Read : 1;
} sss_policy_file_u;

/** All policies related to secure object type Counter */
typedef struct
{
    /** Allow to write the object */
    uint8_t can_Write : 1;
    /** Allow to read the object */
    uint8_t can_Read : 1;
} sss_policy_counter_u;

/** All policies related to secure object type PCR */
typedef struct
{
    /** Allow to write the object */
    uint8_t can_Write : 1;
    /** Allow to read the object */
    uint8_t can_Read : 1;
} sss_policy_pcr_u;

/** All policies related to secure object type UserID */
typedef struct
{
    /** Allow to write the object */
    uint8_t can_Write : 1;
} sss_policy_userid_u;

/** Common Policies for all object types */
typedef struct
{
    /** Forbid all operations */
    uint8_t forbid_All : 1;
    /** Allow to delete the object */
    uint8_t can_Delete : 1;
    /** Require having secure messaging enabled with encryption and integrity on the command */
    uint8_t req_Sm : 1;
} sss_policy_common_u;

/** Common PCR Value Policies for all object types */
typedef struct
{
    /** PCR object ID */
    uint32_t pcrObjId;
    /** Expected value of the PCR */
    uint8_t pcrExpectedValue[32];
} sss_policy_common_pcr_value_u;

/** Unique/individual policy.
 * For any operation, you need array of sss_policy_u.
 */
typedef struct
{
    /** Secure Object Type */
    sss_policy_type_u type;
    /** Auth ID for each Object Policy, invalid for session policy type == KPolicy_Session*/
    uint32_t auth_obj_id;
    /** Union of applicable policies based on the type of object
     */
    union {
        sss_policy_file_u file;
        sss_policy_counter_u counter;
        sss_policy_pcr_u pcr;
        sss_policy_sym_key_u symmkey;
        sss_policy_asym_key_u asymmkey;
        sss_policy_userid_u pin;
        sss_policy_common_u common;
        sss_policy_common_pcr_value_u common_pcr_value;
        sss_policy_session_u session;
    } policy;
} sss_policy_u;

/** An array of policies @ref sss_policy_u */
typedef struct
{
    /** Array of unique policies, this needs to be allocated based  nPolicies */
    const sss_policy_u *policies[SSS_POLICY_COUNT_MAX];
    /** Number of policies */
    size_t nPolicies;
} sss_policy_t;

/** @} */

#endif /* _FSL_SSS_POLICY_H_ */
