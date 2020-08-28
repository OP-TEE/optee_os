/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef SE050X_APDU_APIS_H_INC
#define SE050X_APDU_APIS_H_INC

#include "se05x_enums.h"
#include "se05x_tlv.h"

/** Se05x_API_CreateSession
 *
 * Creates a session on SE05X .
 *
 * Depending on the authentication object being referenced, a specific method of
 * authentication applies. The response needs to adhere to this authentication
 * method.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-------------------+------------------------------+
 * | Field   | Value             | Description                  |
 * +=========+===================+==============================+
 * | CLA     | 0x80              |                              |
 * +---------+-------------------+------------------------------+
 * | INS     | INS_MGMT          | See :cpp:type:`SE05x_INS_t`  |
 * +---------+-------------------+------------------------------+
 * | P1      | P1_DEFAULT        | See :cpp:type:`SE05x_P1_t`   |
 * +---------+-------------------+------------------------------+
 * | P2      | P2_SESSION_CREATE | See :cpp:type:`SE05x_P2_t`   |
 * +---------+-------------------+------------------------------+
 * | Lc      | #(Payload)        | Payload length.              |
 * +---------+-------------------+------------------------------+
 * | Payload | TLV[TAG_1]        | 4-byte authentication object |
 * |         |                   | identifier.                  |
 * +---------+-------------------+------------------------------+
 * | Le      | 0x0A              | Expecting TLV with 8-byte    |
 * |         |                   | session ID.                  |
 * +---------+-------------------+------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------+
 * | Value      | Description                |
 * +============+============================+
 * | TLV[TAG_1] | 8-byte session identifier. |
 * +------------+----------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * SW_NO_ERROR:
 *   * The command is handled successfully.
 *
 * SW_CONDITIONS_NOT_SATISFIED:
 *   * The authenticator does not exist
 *   * The provided input data are incorrect.
 *   * The session is invalid.
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] authObjectID auth [1:kSE05x_TAG_1]
 * @param[out] sessionId  [0:kSE05x_TAG_1]
 * @param[in,out] psessionIdLen Length for sessionId
 *
 *
 */
smStatus_t Se05x_API_CreateSession(
    pSe05xSession_t session_ctx, uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen);

/** Se05x_API_ExchangeSessionData
 *
 * Sets session policies for the current session.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-------------------+-----------------------------+
 * | Field   | Value             | Description                 |
 * +=========+===================+=============================+
 * | CLA     | 0x80 or 0x84      | -                           |
 * +---------+-------------------+-----------------------------+
 * | INS     | INS_MGMT          | See :cpp:type:`SE05x_INS_t` |
 * +---------+-------------------+-----------------------------+
 * | P1      | P1_DEFAULT        | See :cpp:type:`SE05x_P1_t`  |
 * +---------+-------------------+-----------------------------+
 * | P2      | P2_SESSION_POLICY | See P2                      |
 * +---------+-------------------+-----------------------------+
 * | Lc      | #(Payload)        | Payload length.             |
 * +---------+-------------------+-----------------------------+
 * | Payload | TLV[TAG_1]        | Session policies            |
 * +---------+-------------------+-----------------------------+
 * |         | C-MAC             | If applicable               |
 * +---------+-------------------+-----------------------------+
 * | Le      | 0x00              | -                           |
 * +---------+-------------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +-------+----------------------------+
 * | Value | Description                |
 * +=======+============================+
 * | R-MAC | Optional, depending on     |
 * |       | established security level |
 * +-------+----------------------------+
 * @endrst
 *
 *
 * @rst
 * +-----------------------------+------------------------+
 * | SW                          | Description            |
 * +=============================+========================+
 * | SW_NO_ERROR                 | The command is handled |
 * |                             | successfully.          |
 * +-----------------------------+------------------------+
 * | SW_CONDITIONS_NOT_SATISFIED | Invalid policies       |
 * +-----------------------------+------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy Check pdf [1:kSE05x_TAG_1]
 *
 */
smStatus_t Se05x_API_ExchangeSessionData(pSe05xSession_t session_ctx, pSe05xPolicy_t policy);

/** Se05x_API_RefreshSession
 *
 * Refreshes a session on , the policy of the running session can be updated; the
 * rest of the session state remains.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------------+-----------------------------------------------+
 * | Field | Value              | Description                                   |
 * +=======+====================+===============================================+
 * | CLA   | 0x80               | -                                             |
 * +-------+--------------------+-----------------------------------------------+
 * | INS   | INS_MGMT           | See :cpp:type:`SE05x_INS_t`                   |
 * +-------+--------------------+-----------------------------------------------+
 * | P1    | P1_DEFAULT         | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+--------------------+-----------------------------------------------+
 * | P2    | P2_SESSION_REFRESH | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+--------------------+-----------------------------------------------+
 * | Lc    | #(Payload)         | Payload length.                               |
 * +-------+--------------------+-----------------------------------------------+
 * |       | TLV[TAG_POLICY]    | Byte array containing the policy to attach to |
 * |       |                    | the session.   [Optional]                     |
 * +-------+--------------------+-----------------------------------------------+
 * | Le    | -                  |                                               |
 * +-------+--------------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy policy [1:kSE05x_TAG_POLICY]
 */
smStatus_t Se05x_API_RefreshSession(pSe05xSession_t session_ctx, pSe05xPolicy_t policy);

/** Se05x_API_CloseSession
 *
 * Closes a running session.
 *
 * When a session is closed, it cannot be reopened.
 *
 * All session parameters are transient.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------+-----------------------------+
 * | Field | Value            | Description                 |
 * +=======+==================+=============================+
 * | CLA   | 0x80             |                             |
 * +-------+------------------+-----------------------------+
 * | INS   | INS_MGMT         | See :cpp:type:`SE05x_INS_t` |
 * +-------+------------------+-----------------------------+
 * | P1    | P1_DEFAULT       | See :cpp:type:`SE05x_P1_t`  |
 * +-------+------------------+-----------------------------+
 * | P2    | P2_SESSION_CLOSE | See :cpp:type:`SE05x_P2_t`  |
 * +-------+------------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+-------------------------------------+
 * | SW          | Description                         |
 * +=============+=====================================+
 * | SW_NO_ERROR | The session is closed successfully. |
 * +-------------+-------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 */
smStatus_t Se05x_API_CloseSession(pSe05xSession_t session_ctx);

/** Se05x_API_VerifySessionUserID
 *
 * Verifies the session user identifier (UserID) in order to allow setting up a
 * session. If the UserID is correct, the session establishment is successful;
 * otherwise the session cannot be opened (SW_CONDITIONS_NOT_SATISFIED is
 * returned).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+-------------------+-----------------------------+
 * | Field | Value             | Description                 |
 * +=======+===================+=============================+
 * | CLA   | 0x80              |                             |
 * +-------+-------------------+-----------------------------+
 * | INS   | INS_MGMT          | See :cpp:type:`SE05x_INS_t` |
 * +-------+-------------------+-----------------------------+
 * | P1    | P1_DEFAULT        | See :cpp:type:`SE05x_P1_t`  |
 * +-------+-------------------+-----------------------------+
 * | P2    | P2_SESSION_USERID | See :cpp:type:`SE05x_P2_t`  |
 * +-------+-------------------+-----------------------------+
 * | Lc    | #(Payload)        | Payload length.             |
 * +-------+-------------------+-----------------------------+
 * |       | TLV[TAG_1]        | UserID value                |
 * +-------+-------------------+-----------------------------+
 * | Le    | -                 |                             |
 * +-------+-------------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] userId userId [1:kSE05x_TAG_1]
 * @param[in] userIdLen Length of userId
 */
smStatus_t Se05x_API_VerifySessionUserID(pSe05xSession_t session_ctx, const uint8_t *userId, size_t userIdLen);

/** Se05x_API_SetLockState
 *
 * Sets the applet transport lock (locked or unlocked). There is a Persistent
 * lock and a Transient Lock. If the Persistent lock is UNLOCKED, the device is
 * unlocked (regardless of the Transient lock). If the Persistent lock is LOCKED,
 * the device is only unlocked when the Transient lock is UNLOCKED and the device
 * will be locked again after deselect of the applet.
 *
 * Note that regardless of the lock state, the credential RESERVED_ID_TRANSPORT
 * allows access to all features. For example, it is possible to write/update
 * objects within the session opened by RESERVED_ID_TRANSPORT, even if the applet
 * is locked.
 *
 * The default TRANSIENT_LOCK state is LOCKED; there is no default
 * PERSISTENT_LOCK state (depends on product configuration).
 *
 * This command can only be used in a session that used the credential with
 * identifier RESERVED_ID_TRANSPORT as authentication object.
 *
 * @rst
 * +-----------------+----------------+-----------------------------------------------+
 * | PERSISTENT_LOCK | TRANSIENT_LOCK | Behavior                                      |
 * +=================+================+===============================================+
 * | UNLOCKED        | UNLOCKED       | Unlocked until PERSISTENT_LOCK set to LOCKED. |
 * +-----------------+----------------+-----------------------------------------------+
 * | UNLOCKED        | LOCKED         | Unlocked until PERSISTENT_LOCK set to LOCKED. |
 * +-----------------+----------------+-----------------------------------------------+
 * | LOCKED          | UNLOCKED       | Unlocked until deselect or TRANSIENT_LOCK set |
 * |                 |                | to LOCKED.                                    |
 * +-----------------+----------------+-----------------------------------------------+
 * | LOCKED          | LOCKED         | Locked until PERSISTENT_LOCK set to UNLOCKED. |
 * +-----------------+----------------+-----------------------------------------------+
 * @endrst
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+--------------+-------------------------------------+
 * | Field   | Value        | Description                         |
 * +=========+==============+=====================================+
 * | CLA     | 0x80         |                                     |
 * +---------+--------------+-------------------------------------+
 * | INS     | INS_MGMT     | See :cpp:type:`SE05x_INS_t`         |
 * +---------+--------------+-------------------------------------+
 * | P1      | P1_DEFAULT   | See :cpp:type:`SE05x_P1_t`          |
 * +---------+--------------+-------------------------------------+
 * | P2      | P2_TRANSPORT | See :cpp:type:`SE05x_P2_t`          |
 * +---------+--------------+-------------------------------------+
 * | Lc      | #(Payload)   |                                     |
 * +---------+--------------+-------------------------------------+
 * | Payload | TLV[TAG_1]   | 1-byte :cpp:type:`LockIndicatorRef` |
 * +---------+--------------+-------------------------------------+
 * |         | TLV[TAG_2]   | 1-byte :cpp:type:`LockStateRef`     |
 * +---------+--------------+-------------------------------------+
 * | Le      |              |                                     |
 * +---------+--------------+-------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] lockIndicator lock indicator [1:kSE05x_TAG_1]
 * @param[in] lockState lock state [2:kSE05x_TAG_2]
 */
smStatus_t Se05x_API_SetLockState(pSe05xSession_t session_ctx, uint8_t lockIndicator, uint8_t lockState);

/** Se05x_API_SetPlatformSCPRequest
 *
 * Sets the required state for platform SCP (required or not required). This is a
 * persistent state.
 *
 * If platform SCP is set to SCP_REQUIRED, any applet APDU command will be
 * refused by the applet when platform SCP is not enabled. Enabled means full
 * encryption and MAC, both on C-APDU and R-APDU. Any other level is not
 * sufficient and will not be accepted. SCP02 will not be accepted (as there is
 * no response MAC and encryption).
 *
 * If platform SCP is set to "not required," any applet APDU command will be
 * accepted by the applet.
 *
 * This command can only be used in a session that used the credential with
 * identifier RESERVED_ID_PLATFORM_SCP as authentication object.
 *
 * Note that the default state is SCP_NOT_REQUIRED.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+-----------------------------------------------+
 * | Field   | Value      | Description                                   |
 * +=========+============+===============================================+
 * | CLA     | 0x80       |                                               |
 * +---------+------------+-----------------------------------------------+
 * | INS     | INS_MGMT   | See :cpp:type:`SE05x_INS_t`                   |
 * +---------+------------+-----------------------------------------------+
 * | P1      | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | P2      | P2_SCP     | See :cpp:type:`SE05x_P2_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | Lc      | #(Payload) |                                               |
 * +---------+------------+-----------------------------------------------+
 * | Payload | TLV[TAG_1] | 1-byte :cpp:type:`SE05x_PlatformSCPRequest_t` |
 * +---------+------------+-----------------------------------------------+
 * | Le      |            |                                               |
 * +---------+------------+-----------------------------------------------+
 * @endrst
 *
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] platformSCPRequest platf scp req [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_SetPlatformSCPRequest(pSe05xSession_t session_ctx, SE05x_PlatformSCPRequest_t platformSCPRequest);

/** Se05x_API_SetAppletFeatures
 *
 * Sets the applet features that are supported. To successfully execute this
 * command, the session must be authenticated using the RESERVED_ID_FEATURE.
 *
 * The 2-byte input value is a pre-defined AppletConfig value.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+-----------------------------------------------+
 * | Field   | Value      | Description                                   |
 * +=========+============+===============================================+
 * | CLA     | 0x80       |                                               |
 * +---------+------------+-----------------------------------------------+
 * | INS     | INS_MGMT   | See :cpp:type:`SE05x_INS_t`                   |
 * +---------+------------+-----------------------------------------------+
 * | P1      | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | P2      | P2_VARIANT | See :cpp:type:`SE05x_P2_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | Lc      | #(Payload) | Payload length                                |
 * +---------+------------+-----------------------------------------------+
 * | Payload | TLV[TAG_1] | 2-byte Variant from                           |
 * |         |            | :cpp:type:`SE05x_AppletConfig_t`              |
 * +---------+------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] variant variant [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_SetAppletFeatures(pSe05xSession_t session_ctx, pSe05xAppletFeatures_t appletVariant);

/** Se05x_API_WriteECKey
 *
 * Write or update an EC key object.
 *
 * P1KeyPart indicates the key type to be created (if the object does not yet
 * exist).
 *
 * If P1KeyPart = P1_KEY_PAIR, Private Key Value (TLV[TAG_3]) and Public Key
 * Value (TLV[TAG_4) must both be present, or both be absent. If absent, the key
 * pair is generated in the SE05X .
 *
 * If the object already exists, P1KeyPart is ignored.
 *
 * @rst
 * +---------+--------------------------------+------------------------------------------------+
 * | Field   | Value                          | Description                                    |
 * +=========+================================+================================================+
 * | P1      | :cpp:type:`SE05x_KeyPart_t`\|  | See :cpp:type:`SE05x_P1_t`,  P1KeyPart should  |
 * |         | P1_EC                          | only be set for new objects.                   |
 * +---------+--------------------------------+------------------------------------------------+
 * | P2      | P2_DEFAULT                     | See P2                                         |
 * +---------+--------------------------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY]                | Byte array containing the object policy.       |
 * |         |                                | [Optional: default policy applies]             |
 * |         |                                | [Conditional - only when the object            |
 * |         |                                | identifier is not in use yet]                  |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_MAX_ATTEMPTS]          | 2-byte maximum number of attempts. If 0 is     |
 * |         |                                | given, this means unlimited.   [Optional:      |
 * |         |                                | default unlimited]   [Conditional: only when   |
 * |         |                                | the object  identifier is not in use yet and   |
 * |         |                                | INS includes  INS_AUTH_OBJECT; see             |
 * |         |                                | AuthenticationObjectPolicies ]                 |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_POLICY_CHECK]          | Byte array containing the object policy.to be  |
 * |         |                                | compared against.    [Optional: if present,    |
 * |         |                                | the existing policy must match this policy for |
 * |         |                                | the  command to be executed.]                  |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_1]                     | 4-byte object identifier                       |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_2]                     | 1-byte curve identifier, see ECCurve           |
 * |         |                                | [Conditional: only when the object  identifier |
 * |         |                                | is not in use yet; ]                           |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_3]                     | Private key value (see :cpp:type:`ECKeyRef`  ) |
 * |         |                                | [Conditional: only when the private key is     |
 * |         |                                | externally generated and P1KeyPart is either   |
 * |         |                                | P1_KEY_PAIR  or P1_PRIVATE]                    |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_4]                     | Public key value (see :cpp:type:`ECKeyRef`  )  |
 * |         |                                | [Conditional: only when the public key is      |
 * |         |                                | externally generated and P1KeyPart is either   |
 * |         |                                | P1_KEY_PAIR  or P1_PUBLIC]                     |
 * +---------+--------------------------------+------------------------------------------------+
 * |         | TLV[TAG_11]                    | 4-byte version, maximum is 134217727 (or       |
 * |         |                                | 0x7FFFFFFF)..    [Optional]                    |
 * +---------+--------------------------------+------------------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  policy       The policy
 * @param[in]  maxAttempt   The maximum attempt
 * @param[in]  objectID     The object id
 * @param[in]  curveID      The curve id
 * @param[in]  privKey      The priv key
 * @param[in]  privKeyLen   The priv key length
 * @param[in]  pubKey       The pub key
 * @param[in]  pubKeyLen    The pub key length
 * @param[in]  ins_type     The insert type
 * @param[in]  key_part     The key part
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_WriteECKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_ECCurve_t curveID,
    const uint8_t *privKey,
    size_t privKeyLen,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const SE05x_INS_t ins_type,
    const SE05x_KeyPart_t key_part);

/** Se05x_API_WriteRSAKey
 *
 * Creates or writes an RSA key or a key component.
 *
 * Supported key sizes are listed in RSABitLength. Other values are not
 * supported.
 *
 * An RSA key creation requires multiple ADPUs to be sent:
 *
 *   * The first APDU must contain:
 *
 *     * Policy (optional, so only if non-default applies)
 *
 *     * Object identifier
 *
 *     * Key size
 *
 *     * 1 of the key components.
 *
 *   * Each next APDU must contain 1 of the key components.
 *
 * The policy applies only once all key components are set.
 *
 * Once an RSAKey object has been created, its format remains fixed and cannot
 * be updated (so CRT or raw mode, no switch possible).
 *
 * If the object already exists, P1KeyType is ignored.
 *
 * For key pairs, if no component is present (TAG_3 until TAG_9), the key pair
 * will be generated on chip; otherwise the key pair will be constructed
 * starting with the given component.
 *
 * For private keys or public keys, there should always be exactly one of the
 * tags TAG_3 until TAG_10.
 *
 *   * TLV[TAG_8] and TLV[TAG_10] must only contain a value if the key pair is
 *     to be set to a known value and P1KeyType is either P1_KEY_PAIR or
 *     P1_PUBLIC; otherwise the value must be absent and the length must be
 *     equal to 0.
 *
 *   * TLV[TAG_9] must only contain a value it the key is to be set in raw mode
 *     to a known value and P1KeyType is either P1_KEY_PAIR or P1_PRIVATE;
 *     otherwise the value must be absent and the length must be equal to 0.
 *
 *   * If TLV[TAG_3] up to TLV[TAG_10] are absent (except TLV[TAG_8]), the RSA
 *     key will be generated on chip in case the object does not yet exist;
 *     otherwise it will be regenerated. This only applies to RSA key pairs.
 *
 *   * Keys can be set by setting the different components of a key; only 1
 *     component can be set at a time in this case.
 *
 *
 * @rst
 * +---------+-------------------------------+------------------------------------------------+
 * | Field   | Value                         | Description                                    |
 * +=========+===============================+================================================+
 * | P1      | :cpp:type:`SE05x_KeyPart_t` | | See :cpp:type:`SE05x_P1_t`                     |
 * |         | P1_RSA                        |                                                |
 * +---------+-------------------------------+------------------------------------------------+
 * | P2      | P2_DEFAULT or P2_RAW          | See :cpp:type:`SE05x_P2_t`; P2_RAW only in     |
 * |         |                               | case P1KeyPart = P1_KEY_PAIR and  TLV[TAG_3]   |
 * |         |                               | until TLV[TAG_10] is empty and the SE05X  must |
 * |         |                               | generate a raw RSA key pair; all other  cases: |
 * |         |                               | P2_DEFAULT.                                    |
 * +---------+-------------------------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY]               | Byte array containing the object policy.       |
 * |         |                               | [Optional: default policy applies]             |
 * |         |                               | [Conditional: only when the object identifier  |
 * |         |                               | is not in use yet]                             |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_POLICY_CHECK]         | Byte array containing the object policy.to be  |
 * |         |                               | compared against.    [Optional: if present,    |
 * |         |                               | the existing policy must match this policy     |
 * |         |                               | for the command to be executed.]               |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_1]                    | 4-byte object identifier                       |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_2]                    | 2-byte key size in bits                        |
 * |         |                               | (:cpp:type:`SE05x_RSABitLength_t`)             |
 * |         |                               | [Conditional: only when the object identifier  |
 * |         |                               | is not in use yet]                             |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_3]                    | P component   [Conditional: only when the      |
 * |         |                               | object identifier is in CRT mode and the key   |
 * |         |                               | is generated externally and P1KeyPart is       |
 * |         |                               | either P1_KEY_PAIR or P1_PRIVATE]              |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_4]                    | Q component   [Conditional: only when the      |
 * |         |                               | object identifier is in CRT mode and the key   |
 * |         |                               | is generated externally and P1KeyPart is       |
 * |         |                               | either P1_KEY_PAIR or P1_PRIVATE]              |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_5]                    | DP component   [Conditional: only when the     |
 * |         |                               | object identifier is in CRT mode and the key   |
 * |         |                               | is generated externally and P1KeyPart is       |
 * |         |                               | either P1_KEY_PAIR or P1_PRIVATE]              |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_6]                    | DQ component   [Conditional: only when the     |
 * |         |                               | object identifier is in CRT mode and the key   |
 * |         |                               | is generated externally and P1KeyPart is       |
 * |         |                               | either P1_KEY_PAIR or P1_PRIVATE]              |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_7]                    | INV_Q component   [Conditional: only when the  |
 * |         |                               | object identifier is in CRT mode and the key   |
 * |         |                               | is generated externally and P1KeyPart is       |
 * |         |                               | either P1_KEY_PAIR or P1_PRIVATE]              |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_8]                    | Public exponent                                |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_9]                    | Private Key (non-CRT mode only)                |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_10]                   | Public Key (Modulus)                           |
 * +---------+-------------------------------+------------------------------------------------+
 * |         | TLV[TAG_11]                   | 4-byte version, maximum is 134217727 (or       |
 * |         |                               | 0x7FFFFFFF).    [Optional]                     |
 * +---------+-------------------------------+------------------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx     The session context
 * @param[in]  policy          The policy
 * @param[in]  objectID        The object id
 * @param[in]  size            The size
 * @param[in]  p               The part p
 * @param[in]  pLen            The p length
 * @param[in]  q               The quarter
 * @param[in]  qLen            The quarter length
 * @param[in]  dp              The part dp
 * @param[in]  dpLen           The dp length
 * @param[in]  dq              The part dq
 * @param[in]  dqLen           The dq length
 * @param[in]  qInv            The quarter inv
 * @param[in]  qInvLen         The quarter inv length
 * @param[in]  pubExp          The pub exponent
 * @param[in]  pubExpLen       The pub exponent length
 * @param[in]  priv            The priv
 * @param[in]  privLen         The priv length
 * @param[in]  pubMod          The pub modifier
 * @param[in]  pubModLen       The pub modifier length
 * @param[in]  transient_type  The transient type
 * @param[in]  key_part        The key part
 * @param[in]  rsa_format      The rsa format
 *
 * @return     The sm status.
 */

smStatus_t Se05x_API_WriteRSAKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t size,
    const uint8_t *p,
    size_t pLen,
    const uint8_t *q,
    size_t qLen,
    const uint8_t *dp,
    size_t dpLen,
    const uint8_t *dq,
    size_t dqLen,
    const uint8_t *qInv,
    size_t qInvLen,
    const uint8_t *pubExp,
    size_t pubExpLen,
    const uint8_t *priv,
    size_t privLen,
    const uint8_t *pubMod,
    size_t pubModLen,
    const SE05x_INS_t transient_type,
    const SE05x_KeyPart_t key_part,
    const SE05x_RSAKeyFormat_t rsa_format);

/** Se05x_API_WriteSymmKey
 *
 * Creates or writes an AES key, DES key or HMAC key, indicated by P1:
 *
 *   * P1_AES
 *
 *   * P1_DES
 *
 *   * P1_HMAC
 *
 * Users can pass RFC3394 wrapped keys by indicating the KEK in TLV[TAG_2]. Note
 * that RFC3394 required 8-byte aligned input, so this can only be used when the
 * key has an 8-byte aligned length.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------------+------------------------------------------------+
 * | Field   | Value                 | Description                                    |
 * +=========+=======================+================================================+
 * | P1      | See above             | See :cpp:type:`SE05x_P1_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | P2      | P2_DEFAULT            | See :cpp:type:`SE05x_P2_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY]       | Byte array containing the object policy.       |
 * |         |                       | [Optional: default policy applies]             |
 * |         |                       | [Conditional: only when the object identifier  |
 * |         |                       | is not in use yet]                             |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_MAX_ATTEMPTS] | 2-byte maximum number of attempts. If 0 is     |
 * |         |                       | given, this means unlimited.   [Optional:      |
 * |         |                       | default unlimited]   [Conditional: only when   |
 * |         |                       | the object identifier is not in use yet and    |
 * |         |                       | INS includes  INS_AUTH_OBJECT; see             |
 * |         |                       | AuthenticationObjectPolicies]                  |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_POLICY_CHECK] | Byte array containing the object policy.to be  |
 * |         |                       | compared against.    [Optional: if present,    |
 * |         |                       | the existing policy must match this policy     |
 * |         |                       | for the command to be executed.]               |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_1]            | 4-byte object identifier                       |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_2]            | 4-byte KEK identifier   [Conditional: only     |
 * |         |                       | when the key value is RFC3394 wrapped]         |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_3]            | Key value, either plain or RFC3394 wrapped.    |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_4]            | 2-byte minimum tag length for AEAD operations, |
 * |         |                       | minimum is 4 and  maximum is 16.   [Optional:  |
 * |         |                       | default value = 16 bytes]   [Conditional: only |
 * |         |                       | allowed for P1 = P1_AES]                       |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_11]           | 4-byte version, maximum is 134217727 (or       |
 * |         |                       | 0x7FFFFFFF).    [Optional: default value = 0   |
 * |         |                       | (= no versioning)]                             |
 * +---------+-----------------------+------------------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  policy       The policy
 * @param[in]  maxAttempt   The maximum attempt
 * @param[in]  objectID     The object id
 * @param[in]  kekID        The kek id
 * @param[in]  keyValue     The key value
 * @param[in]  keyValueLen  The key value length
 * @param[in]  ins_type     The insert type
 * @param[in]  type         The type
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_WriteSymmKey(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    SE05x_KeyID_t kekID,
    const uint8_t *keyValue,
    size_t keyValueLen,
    const SE05x_INS_t ins_type,
    const SE05x_SymmKeyType_t type);

/** Se05x_API_WriteBinary
 *
 * Creates or writes to a binary file object. Data are written to either the
 * start of the file or (if specified) to the offset passed to the function.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------------+------------------------------------------------+
 * | Field   | Value                 | Description                                    |
 * +=========+=======================+================================================+
 * | P1      | P1_COUNTER            | See :cpp:type:`SE05x_P1_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | P2      | P2_DEFAULT            | See :cpp:type:`SE05x_P2_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY]       | Byte array containing the object policy.       |
 * |         |                       | [Optional: default policy applies]             |
 * |         |                       | [Conditional: only when the object identifier  |
 * |         |                       | is not in use yet]                             |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_POLICY_CHECK] | Byte array containing the object policy.to be  |
 * |         |                       | compared against.    [Optional: if present,    |
 * |         |                       | the existing policy must match this policy     |
 * |         |                       | for the command to be executed.]               |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_1]            | 4-byte counter identifier.                     |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_2]            | 2-byte counter size (1 up to 8 bytes).         |
 * |         |                       | [Conditional: only if object doesn't exist yet |
 * |         |                       | and TAG_3 is not given]                        |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_3]            | Counter value   [Optional: - if object doesn't |
 * |         |                       | exist: must be present if TAG_2 is not given.  |
 * |         |                       | - if object exists: if not present, increment  |
 * |         |                       | by 1. if present, set counter to value.]       |
 * +---------+-----------------------+------------------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy policy [1:kSE05x_TAG_POLICY]
 * @param[in] objectID object id [2:kSE05x_TAG_1]
 * @param[in] offset offset [3:kSE05x_TAG_2]
 * @param[in] length length [4:kSE05x_TAG_3]
 * @param[in] inputData input data [5:kSE05x_TAG_4]
 * @param[in] inputDataLen Length of inputData
 */

smStatus_t Se05x_API_WriteBinary(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    const uint8_t *inputData,
    size_t inputDataLen);

/** Se05x_API_WriteUserID
 *
 * Creates a UserID object, setting the user identifier value. The policy defines
 * the maximum number of attempts that can be performed as comparison.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+-----------------------+-----------------------------------------------+
 * | Field | Value                 | Description                                   |
 * +=======+=======================+===============================================+
 * | P1    | P1_USERID             | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+-----------------------+-----------------------------------------------+
 * | P2    | P2_DEFAULT            | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+-----------------------+-----------------------------------------------+
 * |       | TLV[TAG_POLICY]       | Byte array containing the object policy.      |
 * |       |                       | [Optional: default policy applies]            |
 * |       |                       | [Conditional: only when the object identifier |
 * |       |                       | is not in use yet]                            |
 * +-------+-----------------------+-----------------------------------------------+
 * |       | TLV[TAG_MAX_ATTEMPTS] | 2-byte maximum number of attempts. If 0 is    |
 * |       |                       | given, this means unlimited. For pins, the    |
 * |       |                       | maximum number of attempts must be smaller    |
 * |       |                       | than 256.   [Optional: default = 0]           |
 * |       |                       | [Conditional: only when the object identifier |
 * |       |                       | is not in use yet and INS includes            |
 * |       |                       | INS_AUTH_OBJECT; see :cpp:type:`-`]           |
 * +-------+-----------------------+-----------------------------------------------+
 * |       | TLV[TAG_1]            | 4-byte object identifier.                     |
 * +-------+-----------------------+-----------------------------------------------+
 * |       | TLV[TAG_2]            | Byte array containing 4 to 16 bytes user      |
 * |       |                       | identifier value.                             |
 * +-------+-----------------------+-----------------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx       The session context
 * @param[in]  policy            The policy
 * @param[in]  maxAttempt        The maximum attempt
 * @param[in]  objectID          The object id
 * @param[in]  userId            The user identifier
 * @param[in]  userIdLen         The user identifier length
 * @param[in]  attestation_type  The attestation type
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID,
    const uint8_t *userId,
    size_t userIdLen,
    const SE05x_AttestationType_t attestation_type);

/** Se05x_API_CreateCounter
 *
 * Creates a new counter object.
 *
 * Counters can only be incremented, not decremented.
 *
 * When a counter reaches its maximum value (e.g., 0xFFFFFFFF for a 4-byte
 * counter), they cannot be incremented again.
 *
 * An input value (TAG_3) must always have the same length as the existing
 * counter (if it exists); otherwise the command will return an error.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------+------------------------------------------------+
 * | Field   | Value           | Description                                    |
 * +=========+=================+================================================+
 * | P1      | P1_COUNTER      | See :cpp:type:`SE05x_P1_t`                     |
 * +---------+-----------------+------------------------------------------------+
 * | P2      | P2_DEFAULT      | See :cpp:type:`SE05x_P2_t`                     |
 * +---------+-----------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY] | Byte array containing the object policy.       |
 * |         |                 | [Optional: default policy applies]             |
 * |         |                 | [Conditional: only when the object identifier  |
 * |         |                 | is not in use yet]                             |
 * +---------+-----------------+------------------------------------------------+
 * |         | TLV[TAG_1]      | 4-byte counter identifier.                     |
 * +---------+-----------------+------------------------------------------------+
 * |         | TLV[TAG_2]      | 2-byte counter size (1 up to 8 bytes).         |
 * |         |                 | [Conditional: only if object doesn't exist yet |
 * |         |                 | and TAG_3 is not given]                        |
 * +---------+-----------------+------------------------------------------------+
 * |         | TLV[TAG_3]      | Counter value   [Optional: - if object doesn't |
 * |         |                 | exist: must be present if TAG_2 is not given.  |
 * |         |                 | - if object exists: if not present, increment  |
 * |         |                 | by 1. if present, set counter to value.]       |
 * +---------+-----------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * NA
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy policy [1:kSE05x_TAG_POLICY]
 * @param[in] objectID object id [2:kSE05x_TAG_1]
 * @param[in] size size [3:kSE05x_TAG_2]
 */
smStatus_t Se05x_API_CreateCounter(
    pSe05xSession_t session_ctx, pSe05xPolicy_t policy, uint32_t objectID, uint16_t size);

/** Se05x_API_SetCounterValue
 *
 * See @ref Se05x_API_CreateCounter
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] size size [3:kSE05x_TAG_2]
 * @param[in] value value [4:kSE05x_TAG_3]
 */
smStatus_t Se05x_API_SetCounterValue(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t size, uint64_t value);

/** Se05x_API_IncCounter
 *
 * See @ref Se05x_API_CreateCounter
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_IncCounter(pSe05xSession_t session_ctx, uint32_t objectID);

/** Se05x_API_WritePCR
 *
 * Creates or writes to a PCR object.
 *
 * A PCR is a hash to which data can be appended; i.e., writing data to a PCR
 * will update the value of the PCR to be the hash of all previously inserted
 * data concatenated with the new input data.
 *
 * A PCR will always use DigestMode = DIGEST_SHA256; no other configuration
 * possible.
 *
 * If TAG_2 and TAG_3 is not passed, the PCR is reset to its initial value (i.e.,
 * the value set when the PCR was created).
 *
 * This reset is controlled under the POLICY_OBJ_ALLOW_DELETE policy, so users
 * that can delete the PCR can also reset the PCR to initial value.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------------+------------------------------------------------+
 * | Field   | Value                 | Description                                    |
 * +=========+=======================+================================================+
 * | P1      | P1_PCR                | See :cpp:type:`SE05x_P1_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | P2      | P2_DEFAULT            | See :cpp:type:`SE05x_P2_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | Payload | TLV[TAG_POLICY]       | Byte array containing the object policy.       |
 * |         |                       | [Optional: default policy applies]             |
 * |         |                       | [Conditional: only when the object identifier  |
 * |         |                       | is not in use yet]                             |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_POLICY_CHECK] | Byte array containing the object policy.to be  |
 * |         |                       | compared against.    [Optional: if present,    |
 * |         |                       | the existing policy  must match this policy    |
 * |         |                       | for the command to be  executed.]              |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_1]            | 4-byte PCR identifier.                         |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_2]            | Initial value.   [Conditional: only when the   |
 * |         |                       | object identifier is not in use yet]           |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_3]            | Data to be extended to the existing PCR.       |
 * |         |                       | [Conditional: only when the object identifier  |
 * |         |                       | is already in use]   [Optional: not present if |
 * |         |                       | a Reset is requested]                          |
 * +---------+-----------------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] policy policy [1:kSE05x_TAG_POLICY]
 * @param[in] pcrID object id [2:kSE05x_TAG_1]
 * @param[in] initialValue initialValue [3:kSE05x_TAG_2]
 * @param[in] initialValueLen Length of initialValue
 * @param[in] inputData inputData [4:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_WritePCR(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy,
    uint32_t pcrID,
    const uint8_t *initialValue,
    size_t initialValueLen,
    const uint8_t *inputData,
    size_t inputDataLen);

/** Se05x_API_ImportObject
 *
 * Writes a serialized Secure Object to the SE05X (i.e., "import")
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+-----------------------------------------------+
 * | Field   | Value      | Description                                   |
 * +=========+============+===============================================+
 * | P1      | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | P2      | P2_IMPORT  | See :cpp:type:`SE05x_P2_t`                    |
 * +---------+------------+-----------------------------------------------+
 * | Payload | TLV[TAG_1] | 4-byte identifier.                            |
 * +---------+------------+-----------------------------------------------+
 * |         | TLV[TAG_2] | 1-byte :cpp:type:`SE05x_RSAKeyComponent_t`    |
 * |         |            | [Conditional: only when the identifier refers |
 * |         |            | to an RSAKey object]                          |
 * +---------+------------+-----------------------------------------------+
 * |         | TLV[TAG_3] | Serialized object (encrypted).                |
 * +---------+------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] rsaKeyComp rsaKeyComp [2:kSE05x_TAG_2]
 * @param[in] serializedObject serializedObject [3:kSE05x_TAG_3]
 * @param[in] serializedObjectLen Length of serializedObject
 */
smStatus_t Se05x_API_ImportObject(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAKeyComponent_t rsaKeyComp,
    const uint8_t *serializedObject,
    size_t serializedObjectLen);

/** Se05x_API_ImportExternalObject
 *
 * Combined with the INS_IMPORT_EXTERNAL mask, enables users to send a
 * WriteSecureObject APDU (WriteECKey until WritePCR) protected by a
 * secure channel.
 *
 * Secure Objects can be imported into the SE05X through a secure channel which
 * does not require the establishment of a session. This feature is also referred
 * to single side import and can only be used to create or update objects.
 *
 * The mechanism is based on ECKey session to protect the Secure Object content
 * and is summarized in the following figure.
 *
 * External import flow
 *
 * The flow above can be summarized in the following steps:
 *
 *   1. The user obtains the SE public key for import via the to get
 *      the public key from the device's key pair. Key ID 0x02 will
 *      return the public key of the EC key pair with
 *      RESERVED_ID_EXTERNAL_IMPORT. The response is signed by the
 *      same key pair.
 *
 *   2. The user calls  with input:
 *     * the applet AID (e.g.A0000003965453000000010300000000)
 *
 *     * the SCPparameters
 *
 *       * 1-byte SCP identifier, must equal0xAB
 *
 *       * 2-byte SCP parameter, must equal 0x01 followed by 1-byte
 *         security level (which follows the GlobalPlatform security
 *         level definition, see: .
 *
 *     * key type, must be 0x88 (AES keytype)
 *
 *     * key length, must be 0x10 (AES128key)
 *
 *     * host public key (65-byte NIST P-256 publickey)
 *
 *     * host public key curve identifier (must be 0x03 (=NIST_P256))
 *
 *     * ASN.1 signature over the TLV with tags 0xA6 and0x7F49.
 *
 * The applet will then calculate the master key by performing SHA256
 * over a byte array containing (in order):
 *
 *   * 4-byte counter value being0x00000001
 *
 *   * shared secret (ECDH calculation according [IEEE P1363] using
 *     the private keyfrom RESERVED_ID_ECKEY_SESSION and the public
 *     key provided as input to ECKeySessionInternalAuthenticate. The
 *     length depends on the curve used (e.g. 32 byte for NIST P-256
 *     curve).
 *
 *   * 16-byte random generated by the SE05X.
 *
 *   * 2-byte SCP parameter, must equal 0x01 followed by 1-byte
 *     security level (which follows the GlobalPlatform security level
 *     definition, see: .
 *
 *   * 1-byte keytype
 *
 *   * 1-byte keylength
 *
 * The master key will then be the 16 MSB's of the hash output.
 *
 * Using the master key, the 3 session keys are derived by following the
 * GlobalPlatform specification to derive session keys, e.g. derivation input:
 *
 *   * ENCsession key = CMAC(MK, 00000000000000000000000400008001)
 *
 *   * CMACsession key = CMAC(MK, 00000000000000000000000600008001)
 *
 *   * RMACsession key = CMAC(MK, 00000000000000000000000700008001)
 *
 * The Authentication Object ID needs to be passed using TAG_IMPORT_AUTH_KEY_ID,
 * followed by the Write APDU command (using tag TAG_1).
 *
 * The Write APDU command needs to be constructed as follows:
 *
 *   * Encrypt the command encryption counter (starting with
 *     0x00000000000000000000000000000001) using the S_ENC key. This
 *     becomes the IV for the encrypted APDU.
 *
 *   * Get the APDU command payload and pad it (ISO9797 M2 padding).
 *
 *   * Encrypt the payload in AES CBC mode using the S_ENC key.
 *
 *   * Set the Secure Messaging bit in the CLA (0x04).
 *
 *   * Concatenate the MAC chaining value with the full APDU.
 *
 *   * Then calculate the MAC on this byte array and append the 8-byte
 *     MAC value to the APDU.
 *
 *   * Finally increment the encryption counter for the next command.
 *
 * A receipt will be generated by doing a CMAC operation on the input from tag
 * 0xA6 and 0x7F49 using the RMAC session key,
 *
 * Receipt = CMAC(RMAC session key, <input from TLV 0xA6 and TLV 0x7F49>)
 *
 * There is no need to establish a session; therefore, the ImportExternalObject
 * commands are always sent in the default session. The ImportExternalObject
 * commands are replayable.
 *
 * The P1 and P2 parameters shall be coded as per the intended operation. For
 * example, to import an EC Key, the P1 and P2 parameters as defined in
 * WriteECKey shall be specified.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------------------+---------------------------------------------+
 * | Field   | Value                       | Description                                 |
 * +=========+=============================+=============================================+
 * | CLA     | 0x80                        |                                             |
 * +---------+-----------------------------+---------------------------------------------+
 * | INS     | INS_IMPORT_EXTERNAL         | See :cpp:type:`SE05x_INS_t`                 |
 * +---------+-----------------------------+---------------------------------------------+
 * | P1      | P1_DEFAULT                  | See :cpp:type:`SE05x_P1_t`                  |
 * +---------+-----------------------------+---------------------------------------------+
 * | P2      | P2_DEFAULT                  | See :cpp:type:`SE05x_P2_t`                  |
 * +---------+-----------------------------+---------------------------------------------+
 * | Lc      | #(Payload)                  |                                             |
 * +---------+-----------------------------+---------------------------------------------+
 * | Payload | TLV[TAG_IMPORT_AUTH_DATA]   | Authentication data                         |
 * +---------+-----------------------------+---------------------------------------------+
 * |         | TLV[TAG_IMPORT_AUTH_KEY_ID] | Host public key Identifier                  |
 * +---------+-----------------------------+---------------------------------------------+
 * |         | TLV[TAG_1]...               | Wraps a complete WriteSecureObject command, |
 * |         |                             | protected by ECKey session secure messaging |
 * +---------+-----------------------------+---------------------------------------------+
 * |         | TLV[TAG_11]                 | 4-byte version    [Optional]                |
 * +---------+-----------------------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] ECKeydata ECKeydata [1:kSE05x_TAG_2]
 * @param[in] ECKeydataLen Length of ECKeydata
 * @param[in] serializedObject serializedObject [2:kSE05x_TAG_3]
 * @param[in] serializedObjectLen Length of serializedObject
 */
smStatus_t Se05x_API_ImportExternalObject(pSe05xSession_t session_ctx,
    const uint8_t *ECKeydata,
    size_t ECKeydataLen,
    const uint8_t *ECAuthKeyID,
    size_t ECAuthKeyIDLen,
    const uint8_t *serializedObject,
    size_t serializedObjectLen);

/** Se05x_API_ReadObject
 *
 * Reads the content of a Secure Object.
 *
 *  * If the object is a key pair, the command will return the key
 *    pair's public key.
 *
 *  * If the object is a public key, the command will return the public
 *    key.
 *
 *  * If the object is a private key or a symmetric key or a userID,
 *    the command will return SW_CONDITIONS_NOT_SATISFIED.
 *
 *  * If the object is a binary file, the file content is read, giving
 *    the offset in TLV[TAG_2] and the length to read in
 *    TLV[TAG_3]. Both TLV[TAG_2] and TLV[TAG_3] are bound together;
 *    i.e.. either both tags are present, or both are absent. If both
 *    are absent, the whole file content is returned.
 *
 *  * If the object is a monotonic counter, the counter value is
 *    returned.
 *
 *  * If the object is a PCR, the PCR value is returned.
 *
 *  * If TLV[TAG_4] is filled, only the modulus or public exponent of
 *    an RSA key pair or RSA public key is read. It does not apply to
 *    other Secure Object types.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+----------------------------------------------+
 * | Field | Value      | Description                                  |
 * +=======+============+==============================================+
 * | CLA   | 0x80       |                                              |
 * +-------+------------+----------------------------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t`, in addition to  |
 * |       |            | INS_READ, users can set the INS_ATTEST flag. |
 * |       |            | In that case, attestation applies.           |
 * +-------+------------+----------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------+----------------------------------------------+
 * | P2    | P2_DEFAULT | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------+----------------------------------------------+
 * | Lc    | #(Payload) | Payload Length.                              |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte object identifier                     |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_2] | 2-byte offset   [Optional: default 0]        |
 * |       |            | [Conditional: only when the object is a      |
 * |       |            | BinaryFile object]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_3] | 2-byte length   [Optional: default 0]        |
 * |       |            | [Conditional: only when the object is a      |
 * |       |            | BinaryFile object]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_4] | 1-byte :cpp:type:`SE05x_RSAKeyComponent_t`:  |
 * |       |            | either RSA_COMP_MOD or RSA_COMP_PUB_EXP.     |
 * |       |            | [Optional]   [Conditional: only for RSA key  |
 * |       |            | components]                                  |
 * +-------+------------+----------------------------------------------+
 * | Le    | 0x00       |                                              |
 * +-------+------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_1] | Data read from the secure object.          |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | The read is done successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] offset offset [2:kSE05x_TAG_2]
 * @param[in] length length [3:kSE05x_TAG_3]
 * @param[out] data  [0:kSE05x_TAG_1]
 * @param[in,out] pdataLen Length for data
 */
smStatus_t Se05x_API_ReadObject(
    pSe05xSession_t session_ctx, uint32_t objectID, uint16_t offset, uint16_t length, uint8_t *data, size_t *pdataLen);

/** Se05x_API_ReadObject_W_Attst
 *
 * Read with attestation.
 *
 * See @ref Se05x_API_ReadObject
 *
 * When INS_ATTEST is set in addition to INS_READ, the secure object is read with
 * attestation. In addition to the response in TLV[TAG_1], there are additional
 * tags:
 *
 * TLV[TAG_2] will hold the object attributes (see ObjectAttributes).
 *
 * TLV[TAG_3] relative timestamp when the object has been retrieved
 *
 * TLV[TAG_4] will hold freshness random data
 *
 * TLV[TAG_5] will hold the unique ID of the device.
 *
 * TLV[TAG_6] will hold the signature over all concatenated Value fields tags of
 * the response (TAG_1 until and including TAG_5).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+----------------------------------------------+
 * | Field | Value      | Description                                  |
 * +=======+============+==============================================+
 * | CLA   | 0x80       |                                              |
 * +-------+------------+----------------------------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t`, in addition to  |
 * |       |            | INS_READ, users can set the INS_ATTEST flag. |
 * |       |            | In that case, attestation applies.           |
 * +-------+------------+----------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------+----------------------------------------------+
 * | P2    | P2_DEFAULT | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------+----------------------------------------------+
 * | Lc    | #(Payload) | Payload Length.                              |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte object identifier                     |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_2] | 2-byte offset   [Optional: default 0]        |
 * |       |            | [Conditional: only when the object is a      |
 * |       |            | BinaryFile object]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_3] | 2-byte length   [Optional: default 0]        |
 * |       |            | [Conditional: only when the object is a      |
 * |       |            | BinaryFile object]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_4] | 1-byte :cpp:type:`SE05x_RSAKeyComponent_t`:  |
 * |       |            | either RSA_COMP_MOD or RSA_COMP_PUB_EXP.     |
 * |       |            | [Optional]   [Conditional: only for RSA key  |
 * |       |            | components]                                  |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_5] | 4-byte attestation object identifier.        |
 * |       |            | [Optional]   [Conditional: only when         |
 * |       |            | INS_ATTEST is set]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_6] | 1-byte :cpp:type:`SE05x_AttestationAlgo_t`   |
 * |       |            | [Optional]   [Conditional: only when         |
 * |       |            | INS_ATTEST is set]                           |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_7] | 16-byte freshness random   [Optional]        |
 * |       |            | [Conditional: only when INS_ATTEST is set]   |
 * +-------+------------+----------------------------------------------+
 * | Le    | 0x00       |                                              |
 * +-------+------------+----------------------------------------------+
 * @endrst
 *
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_1] | Data read from the secure object.          |
 * +------------+--------------------------------------------+
 * | TLV[TAG_2] | (only when INS_ATTEST is set) Byte array   |
 * |            | containing the attributes (see             |
 * |            | :cpp:type:`ObjectAttributesRef`).          |
 * +------------+--------------------------------------------+
 * | TLV[TAG_3] | (only when INS_ATTEST is set) 12-byte      |
 * |            | timestamp                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_4] | (only when INS_ATTEST is set) 16-byte      |
 * |            | freshness random                           |
 * +------------+--------------------------------------------+
 * | TLV[TAG_5] | (only when INS_ATTEST is set) 18-byte Chip |
 * |            | unique ID                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_6] | (only when INS_ATTEST is set) Signature    |
 * |            | applied over the value of TLV[TAG_1],      |
 * |            | TLV[TAG_2], TLV[TAG_3], TLV[TAG_4] and     |
 * |            | TLV[TAG_5].                                |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_1] | Data read from the secure object.          |
 * +------------+--------------------------------------------+
 * | TLV[TAG_2] | (only when INS_ATTEST is set) Byte array   |
 * |            | containing the attributes (see             |
 * |            | :cpp:type:`ObjectAttributesRef`).          |
 * +------------+--------------------------------------------+
 * | TLV[TAG_3] | (only when INS_ATTEST is set) 12-byte      |
 * |            | timestamp                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_4] | (only when INS_ATTEST is set) 16-byte      |
 * |            | freshness random                           |
 * +------------+--------------------------------------------+
 * | TLV[TAG_5] | (only when INS_ATTEST is set) 18-byte Chip |
 * |            | unique ID                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_6] | (only when INS_ATTEST is set) Signature    |
 * |            | applied over the value of TLV[TAG_1],      |
 * |            | TLV[TAG_2], TLV[TAG_3], TLV[TAG_4] and     |
 * |            | TLV[TAG_5].                                |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx    The session context
 * @param[in]  objectID       The object id
 * @param[in]  offset         The offset
 * @param[in]  length         The length
 * @param[in]  attestID       The attest id
 * @param[in]  attestAlgo     The attest algorithm
 * @param[in]  random         The random
 * @param[in]  randomLen      The random length
 * @param      data           The data
 * @param      pdataLen       The pdata length
 * @param      attribute      The attribute
 * @param      pattributeLen  The pattribute length
 * @param      ptimeStamp     The ptime stamp
 * @param      outrandom      The outrandom
 * @param      poutrandomLen  The poutrandom length
 * @param      chipId         The chip identifier
 * @param      pchipIdLen     The pchip identifier length
 * @param      signature      The signature
 * @param      psignatureLen  The psignature length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ReadObject_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *data,
    size_t *pdataLen,
    uint8_t *attribute,
    size_t *pattributeLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *outrandom,
    size_t *poutrandomLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_ReadRSA
 *
 * See @ref Se05x_API_ReadObject
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] offset offset [2:kSE05x_TAG_2]
 * @param[in] length length [3:kSE05x_TAG_3]
 * @param[in] rsa_key_comp rsa_key_comp [4:kSE05x_TAG_4]
 * @param[out] data  [0:kSE05x_TAG_1]
 * @param[in,out] pdataLen Length for data
 */
smStatus_t Se05x_API_ReadRSA(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    SE05x_RSAPubKeyComp_t rsa_key_comp,
    uint8_t *data,
    size_t *pdataLen);

/**  Se05x_API_ReadRSA_W_Attst
 *
 * See @ref Se05x_API_ReadObject_W_Attst
 *
 * @param[in]  session_ctx    The session context
 * @param[in]  objectID       The object id
 * @param[in]  offset         The offset
 * @param[in]  length         The length
 * @param[in]  rsa_key_comp   The rsa key component
 * @param[in]  attestID       The attest id
 * @param[in]  attestAlgo     The attest algorithm
 * @param[in]  random         The random
 * @param[in]  randomLen      The random length
 * @param      data           The data
 * @param      pdataLen       The pdata length
 * @param      attribute      The attribute
 * @param      pattributeLen  The pattribute length
 * @param      ptimeStamp     The ptime stamp
 * @param      outrandom      The outrandom
 * @param      poutrandomLen  The poutrandom length
 * @param      chipId         The chip identifier
 * @param      pchipIdLen     The pchip identifier length
 * @param      signature      The signature
 * @param      psignatureLen  The psignature length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ReadRSA_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint16_t offset,
    uint16_t length,
    SE05x_RSAPubKeyComp_t rsa_key_comp,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *data,
    size_t *pdataLen,
    uint8_t *attribute,
    size_t *pattributeLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *outrandom,
    size_t *poutrandomLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_ReadObjectAttributes_W_Attst
 *
 * Reads the attributes of a Secure Object (without the value of the Secure
 * Object).
 *
 * Each Secure Object has a number of attributes assigned to it. These attributes
 * are listed in  for Authentication Objects and in  for non-Authentication
 * Objects.
 *
 * # Authentication Object attributes
 *
 * @rst
 * +----------------------------------+--------------+------------------------------------------------+
 * | Attribute                        | Size (bytes) | Description                                    |
 * +==================================+==============+================================================+
 * | Object identifier                | 4            | See :cpp:type:`identifiersRef`                 |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Object type                      | 1            | One of SecureObjectType                        |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Authentication attribute         | 1            | One of :cpp:type:`SetIndicatorRef`             |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Object counter                   | 2            | Number of failed attempts for an               |
 * |                                  |              | authentication object if the Maximum           |
 * |                                  |              | Authentication Attempts has been set.          |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Authentication object identifier | 4            | "Owner" of the secure object; i.e., the        |
 * |                                  |              | identifier of the session  authentication      |
 * |                                  |              | object when the object has been created.       |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Maximum authentication attempts  | 2            | Maximum number of authentication attempts. 0   |
 * |                                  |              | means unlimited.                               |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Policy                           | Variable     | Policy attached to the object                  |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Origin                           | 1            | One of :cpp:type:`OriginRef`; indicates the    |
 * |                                  |              | origin  of the Secure Object, either           |
 * |                                  |              | externally set, internally generated or  trust |
 * |                                  |              | provisioned by NXP.                            |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Version                          | 1            | The Secure Object version. Default = 0. See    |
 * |                                  |              | FIPS compliance for details about versioning   |
 * |                                  |              | of Secure  Objects.                            |
 * +----------------------------------+--------------+------------------------------------------------+
 * @endrst
 *
 * # Non-Authentication Objects
 *
 * @rst
 * +----------------------------------+--------------+------------------------------------------------+
 * | Attribute                        | Size (bytes) | Description                                    |
 * +==================================+==============+================================================+
 * | Object identifier                | 4            | See Object  identifiers                        |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Object type                      | 1            | One of SecureObjectType                        |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Authentication attribute         | 1            | One of :cpp:type:`SetIndicatorRef`             |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Tag length                       | 2            | Set to 0x0000, except for AESKey objects: for  |
 * |                                  |              | AESKey objects, this  indicates the GMAC       |
 * |                                  |              | length that applies when doing AEAD            |
 * |                                  |              | operations.  If the value is set to 0 and AEAD |
 * |                                  |              | operations are done, the GMAC  length shall be |
 * |                                  |              | 128 bit.                                       |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Authentication object identifier | 4            | "Owner" of the secure object; i.e., the        |
 * |                                  |              | identifier of the session  authentication      |
 * |                                  |              | object when the object has been created.       |
 * +----------------------------------+--------------+------------------------------------------------+
 * | RFU                              | 2            | Set to 0x0000.                                 |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Policy                           | Variable     | Policy attached to the object                  |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Origin                           | 1            | One of :cpp:type:`OriginRef`; indicates the    |
 * |                                  |              | origin  of the Secure Object, either           |
 * |                                  |              | externally set, internally generated or  trust |
 * |                                  |              | provisioned by NXP.                            |
 * +----------------------------------+--------------+------------------------------------------------+
 * | Version                          | 1            | The Secure Object version. Default = 0. See    |
 * |                                  |              | FIPS compliance for details about versioning   |
 * |                                  |              | of Secure  Objects.                            |
 * +----------------------------------+--------------+------------------------------------------------+
 * @endrst
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------+-----------------------------------------------+
 * | Field | Value         | Description                                   |
 * +=======+===============+===============================================+
 * | CLA   | 0x80          |                                               |
 * +-------+---------------+-----------------------------------------------+
 * | INS   | INS_READ      | See :cpp:type:`SE05x_INS_t`, in addition to   |
 * |       |               | INS_READ, users  can set the INS_ATTEST flag. |
 * |       |               | In that case, attestation applies.            |
 * +-------+---------------+-----------------------------------------------+
 * | P1    | P1_DEFAULT    | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+---------------+-----------------------------------------------+
 * | P2    | P2_ATTRIBUTES | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+---------------+-----------------------------------------------+
 * | Lc    | #(Payload)    | Payload Length.                               |
 * +-------+---------------+-----------------------------------------------+
 * |       | TLV[TAG_1]    | 4-byte object identifier                      |
 * +-------+---------------+-----------------------------------------------+
 * |       | TLV[TAG_5]    | 4-byte attestation object identifier.         |
 * |       |               | [Optional]   [Conditional: only when          |
 * |       |               | INS_ATTEST is set]                            |
 * +-------+---------------+-----------------------------------------------+
 * |       | TLV[TAG_6]    | 1-byte AttestationAlgo   [Optional]           |
 * |       |               | [Conditional: only when INS_ATTEST is set]    |
 * +-------+---------------+-----------------------------------------------+
 * |       | TLV[TAG_7]    | 16-byte freshness random   [Optional]         |
 * |       |               | [Conditional: only when INS_ATTEST is set]    |
 * +-------+---------------+-----------------------------------------------+
 * | Le    | 0x00          |                                               |
 * +-------+---------------+-----------------------------------------------+
 * @endrst
 *
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_2] | Byte array containing the attributes (see  |
 * |            | Object  Attributes).                       |
 * +------------+--------------------------------------------+
 * | TLV[TAG_3] | (only when INS_ATTEST is set) 12-byte      |
 * |            | timestamp                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_4] | (only when INS_ATTEST is set) 16-byte      |
 * |            | freshness random                           |
 * +------------+--------------------------------------------+
 * | TLV[TAG_5] | (only when INS_ATTEST is set) 18-byte Chip |
 * |            | unique ID                                  |
 * +------------+--------------------------------------------+
 * | TLV[TAG_6] | (only when INS_ATTEST is set) Signature    |
 * |            | applied over the value of TLV[TAG_2],      |
 * |            | TLV[TAG_2], TLV[TAG_3], TLV[TAG_4] and     |
 * |            | TLV[TAG_5].                                |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | The read is done successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx    The session context
 * @param[in]  objectID       The object id
 * @param[in]  attestID       The attest id
 * @param[in]  attestAlgo     The attest algorithm
 * @param[in]  random         The random
 * @param[in]  randomLen      The random length
 * @param      data           The data
 * @param      pdataLen       The pdata length
 * @param      ptimeStamp     The ptime stamp
 * @param      outrandom      The outrandom
 * @param      poutrandomLen  The poutrandom length
 * @param      chipId         The chip identifier
 * @param      pchipIdLen     The pchip identifier length
 * @param      signature      The signature
 * @param      psignatureLen  The psignature length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ReadObjectAttributes_W_Attst(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint32_t attestID,
    SE05x_AttestationAlgo_t attestAlgo,
    const uint8_t *random,
    size_t randomLen,
    uint8_t *data,
    size_t *pdataLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *outrandom,
    size_t *poutrandomLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_ExportObject
 *
 * Reads a transient Secure Object from SE05X.
 *
 * Secure Objects can be serialized so the Secure Object can be represented as a
 * byte array. The byte array contains all attributes of the Secure Object, as
 * well as the value (including the secret part!) of the object.
 *
 * The purpose of the serialization is to be able to allow export and import of
 * Secure Objects. Serialized Secure Objects can be reconstructed so they can be
 * used as a (normal) Secure Object. Any operation like key or file management
 * and crypto operation can only be done on a deserialized Secure Object.
 *
 * Users can export transient Secure Objects to a non-trusted environment (e.g.,
 * host controller). The object must be AESKey, DESKey, RSAKey or ECCKey.
 *
 * Exported credentials are always encrypted and MAC'ed.
 *
 * The following steps are taken:
 *
 *   * The secure element holds a randomly generated persistent
 *     256-bit AES cipher and an 128-bit AES CMAC key. Both keys do
 *     not require user interaction, they are internal to the SE05X .
 *
 *   * A Secure Object that is identified for export is
 *     serialized. This means the key value as well as all Secure
 *     Object attributes are stored as byte array (see Object
 *     attributes for attribute details).
 *
 *   * The serialized Secure Object is encrypted using AES CBC (no
 *     padding) and using the default IV.
 *
 *   * A CMAC is applied to the serialized Secure Object + metadata
 *     using the AES CMAC key.
 *
 *   * The byte array is exported.
 *
 * An object may only be imported into the store if the SecureObject ID and type
 * are the same as the exported object. Therefore, it is not possible to import
 * if the corresponding object in the applet has been deleted.
 *
 * NOTES:
 *
 *   * The exported object is not deleted automatically.
 *
 *   * The timestamp has a 100msec granularity, so it is possible to
 *     export multiple times with the same timestamp. The freshness
 *     (user input) should avoid duplicate attestation results as the
 *     user has to provide different freshness input.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+--------------------------------------------+
 * | Field | Value      | Description                                |
 * +=======+============+============================================+
 * | CLA   | 0x80       |                                            |
 * +-------+------------+--------------------------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t`.               |
 * +-------+------------+--------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                 |
 * +-------+------------+--------------------------------------------+
 * | P2    | P2_EXPORT  | See :cpp:type:`SE05x_P2_t`                 |
 * +-------+------------+--------------------------------------------+
 * | Lc    | #(Payload) | Payload Length.                            |
 * +-------+------------+--------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte object identifier                   |
 * +-------+------------+--------------------------------------------+
 * |       | TLV[TAG_2] | 1-byte :cpp:type:`SE05x_RSAKeyComponent_t` |
 * |       |            | (only applies to Secure Objects of type    |
 * |       |            | RSAKey).                                   |
 * +-------+------------+--------------------------------------------+
 * | Le    | 0x00       |                                            |
 * +-------+------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------------------+
 * | Value      | Description                                  |
 * +============+==============================================+
 * | TLV[TAG_1] | Byte array containing exported Secure Object |
 * |            | data.                                        |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+----------------------------------------------+
 * | SW          | Description                                  |
 * +=============+==============================================+
 * | SW_NO_ERROR | The file is created or updated successfully. |
 * +-------------+----------------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[in] rsaKeyComp rsaKeyComp [2:kSE05x_TAG_2]
 * @param[out] data  [0:kSE05x_TAG_1]
 * @param[in,out] pdataLen Length for data
 */
smStatus_t Se05x_API_ExportObject(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAKeyComponent_t rsaKeyComp,
    uint8_t *data,
    size_t *pdataLen);

/** Se05x_API_ReadType
 *
 * Get the type of a Secure Object.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-----------------------------+
 * | Field | Value      | Description                 |
 * +=======+============+=============================+
 * | CLA   | 0x80       |                             |
 * +-------+------------+-----------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t` |
 * +-------+------------+-----------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`  |
 * +-------+------------+-----------------------------+
 * | P2    | P2_TYPE    | See :cpp:type:`SE05x_P2_t`  |
 * +-------+------------+-----------------------------+
 * | Lc    | #(Payload) |                             |
 * +-------+------------+-----------------------------+
 * |       | TLV[TAG_1] | 4-byte object identifier.   |
 * +-------+------------+-----------------------------+
 * | Le    | 0x00       |                             |
 * +-------+------------+-----------------------------+
 * @endrst
 *

 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------------+
 * | Value      | Description                       |
 * +============+===================================+
 * | TLV[TAG_1] | Type of the Secure Object: one of |
 * |            | :cpp:type:`SE05x_SecObjTyp_t`     |
 * +------------+-----------------------------------+
 * | TLV[TAG_2] | :cpp:type:`TransientIndicatorRef` |
 * +------------+-----------------------------------+
 * @endrst
 *
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 * @param[in]  session_ctx       The session context
 * @param[in]  objectID          The object id
 * @param      ptype             The ptype
 * @param      pisTransient      The pis transient
 * @param[in]  attestation_type  The attestation type
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ReadType(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_SecureObjectType_t *ptype,
    uint8_t *pisTransient,
    const SE05x_AttestationType_t attestation_type);

/** Se05x_API_ReadSize
 *
 * ReadSize
 *
 * Get the size of a Secure Object (in bytes):
 *
 *   * For EC keys: the size of the curve is returned.
 *
 *   * For RSA keys: the key size is returned.
 *
 *   * For AES/DES/HMAC keys, the key size is returned.
 *
 *   * For binary files: the file size is returned
 *
 *   * For userIDs: nothing is returned (SW_CONDITIONS_NOT_SATISFIED).
 *
 *   * For counters: the counter length is returned.
 *
 *   * For PCR: the PCR length is returned.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-----------------------------+
 * | Field | Value      | Description                 |
 * +=======+============+=============================+
 * | CLA   | 0x80       |                             |
 * +-------+------------+-----------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t` |
 * +-------+------------+-----------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`  |
 * +-------+------------+-----------------------------+
 * | P2    | P2_SIZE    | See :cpp:type:`SE05x_P2_t`  |
 * +-------+------------+-----------------------------+
 * | Lc    | #(Payload) |                             |
 * +-------+------------+-----------------------------+
 * |       | TLV[TAG_1] | 4-byte object identifier.   |
 * +-------+------------+-----------------------------+
 * | Le    | 0x00       |                             |
 * +-------+------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------+
 * | Value      | Description                 |
 * +============+=============================+
 * | TLV[TAG_1] | Byte array containing size. |
 * +------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  objectID     The object id
 * @param      psize        The psize
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_ReadSize(pSe05xSession_t session_ctx, uint32_t objectID, uint16_t *psize);

/** Se05x_API_ReadIDList
 *
 * Get a list of present Secure Object identifiers.
 *
 * The offset in TAG_1 is an 0-based offset in the list of object. As the user
 * does not know how many objects would be returned, the offset needs to be based
 * on the return values from the previous ReadIDList. If the applet only returns
 * a part of the result, it will indicate that more identifiers are available (by
 * setting TLV[TAG_1] in the response to 0x01). The user can then retrieve the
 * next chunk of identifiers by calling ReadIDList with an offset that equals the
 * amount of identifiers listed in the previous response.
 *
 * _Example 1:_ first ReadIDList command TAG_1=0, response TAG_1=0,
 * TAG_2=complete list
 *
 * _Example 2:_ first ReadIDList command TAG_1=0, response TAG_1=1, TAG_2=first
 * chunk (m entries) second ReadIDList command TAG_1=m, response TAG_1=1,
 * TAG_2=second chunk (n entries) thirst ReadIDList command TAG_1=(m+n), response
 * TAG_1=0, TAG_2=third last chunk
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-----------------------------------------------+
 * | Field | Value      | Description                                   |
 * +=======+============+===============================================+
 * | CLA   | 0x80       |                                               |
 * +-------+------------+-----------------------------------------------+
 * | INS   | INS_READ   | See :cpp:type:`SE05x_INS_t`                   |
 * +-------+------------+-----------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+------------+-----------------------------------------------+
 * | P2    | P2_LIST    | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+------------+-----------------------------------------------+
 * | Lc    | #(Payload) |                                               |
 * +-------+------------+-----------------------------------------------+
 * |       | TLV[TAG_1] | 2-byte offset                                 |
 * +-------+------------+-----------------------------------------------+
 * |       | TLV[TAG_2] | 1-byte type filter: 1 byte from               |
 * |       |            | :cpp:type:`SE05x_SecObjTyp_t` or 0xFF for all |
 * |       |            | types.                                        |
 * +-------+------------+-----------------------------------------------+
 * | Le    | 0x00       |                                               |
 * +-------+------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------------------------------------+
 * | Value      | Description                               |
 * +============+===========================================+
 * | TLV[TAG_1] | 1-byte :cpp:type:`MoreIndicatorRef`       |
 * +------------+-------------------------------------------+
 * | TLV[TAG_2] | Byte array containing 4-byte identifiers. |
 * +------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] outputOffset output offset [1:kSE05x_TAG_1]
 * @param[in] filter filter [2:kSE05x_TAG_2]
 * @param[out] pmore If more ids are present [0:kSE05x_TAG_1]
 * @param[out] idlist Byte array containing 4-byte identifiers [1:kSE05x_TAG_2]
 * @param[in,out] pidlistLen Length for idlist
 */
smStatus_t Se05x_API_ReadIDList(pSe05xSession_t session_ctx,
    uint16_t outputOffset,
    uint8_t filter,
    uint8_t *pmore,
    uint8_t *idlist,
    size_t *pidlistLen);

/** Se05x_API_CheckObjectExists
 *
 *
 * Check if a Secure Object with a certain identifier exists or not.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-------------------------------------------+
 * | Field | Value      | Description                               |
 * +=======+============+===========================================+
 * | CLA   | 0x80       |                                           |
 * +-------+------------+-------------------------------------------+
 * | INS   | INS_MGMT   | See :cpp:type:`SE05x_INS_t`               |
 * +-------+------------+-------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                |
 * +-------+------------+-------------------------------------------+
 * | P2    | P2_EXIST   | See :cpp:type:`SE05x_P2_t`                |
 * +-------+------------+-------------------------------------------+
 * | Lc    | #(Payload) |                                           |
 * +-------+------------+-------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte existing Secure Object identifier. |
 * +-------+------------+-------------------------------------------+
 * | Le    | 0x00       |                                           |
 * +-------+------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------------+
 * | Value      | Description                       |
 * +============+===================================+
 * | TLV[TAG_1] | 1-byte :cpp:type:`SE05x_Result_t` |
 * +------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[out] presult  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_CheckObjectExists(pSe05xSession_t session_ctx, uint32_t objectID, SE05x_Result_t *presult);

/** Se05x_API_DeleteSecureObject
 *
 * Deletes a Secure Object.
 *
 * If the object origin = ORIGIN_PROVISIONED, an error will be returned and the
 * object is not deleted.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------+-------------------------------------------+
 * | Field | Value            | Description                               |
 * +=======+==================+===========================================+
 * | CLA   | 0x80             |                                           |
 * +-------+------------------+-------------------------------------------+
 * | INS   | INS_MGMT         | See :cpp:type:`SE05x_INS_t`               |
 * +-------+------------------+-------------------------------------------+
 * | P1    | P1_DEFAULT       | See :cpp:type:`SE05x_P1_t`                |
 * +-------+------------------+-------------------------------------------+
 * | P2    | P2_DELETE_OBJECT | See :cpp:type:`SE05x_P2_t`                |
 * +-------+------------------+-------------------------------------------+
 * | Lc    | #(Payload)       |                                           |
 * +-------+------------------+-------------------------------------------+
 * |       | TLV[TAG_1]       | 4-byte existing Secure Object identifier. |
 * +-------+------------------+-------------------------------------------+
 * | Le    | -                |                                           |
 * +-------+------------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+----------------------------------------------+
 * | SW          | Description                                  |
 * +=============+==============================================+
 * | SW_NO_ERROR | The file is created or updated successfully. |
 * +-------------+----------------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_DeleteSecureObject(pSe05xSession_t session_ctx, uint32_t objectID);

/** Se05x_API_CreateECCurve
 *
 * Create an EC curve listed in ECCurve.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-------------------------------+
 * | Field | Value      | Description                   |
 * +=======+============+===============================+
 * | CLA   | 0x80       |                               |
 * +-------+------------+-------------------------------+
 * | INS   | INS_WRITE  | See :cpp:type:`SE05x_INS_t`   |
 * +-------+------------+-------------------------------+
 * | P1    | P1_CURVE   | See :cpp:type:`SE05x_P1_t`    |
 * +-------+------------+-------------------------------+
 * | P2    | P2_CREATE  | See :cpp:type:`SE05x_P2_t`    |
 * +-------+------------+-------------------------------+
 * | Lc    | #(Payload) |                               |
 * +-------+------------+-------------------------------+
 * |       | TLV[TAG_1] | 1-byte curve identifier (from |
 * |       |            | :cpp:type:`SE05x_ECCurve_t`). |
 * +-------+------------+-------------------------------+
 * | Le    |            |                               |
 * +-------+------------+-------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] curveID curve id [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_CreateECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID);

/** Se05x_API_SetECCurveParam
 *
 * Set a curve parameter. The curve must have been created first by
 * CreateEcCurve.
 *
 * All parameters must match the expected value for the listed curves. If the
 * curve parameters are not correct, the curve cannot be used.
 *
 * Users have to set all 5 curve parameters for the curve to be usable. Once all
 * curve parameters are given, the secure element will check if all parameters
 * are correct and return SW_NO_ERROR..
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+----------------------------------------------+
 * | Field | Value      | Description                                  |
 * +=======+============+==============================================+
 * | CLA   | 0x80       |                                              |
 * +-------+------------+----------------------------------------------+
 * | INS   | INS_WRITE  | See :cpp:type:`SE05x_INS_t`                  |
 * +-------+------------+----------------------------------------------+
 * | P1    | P1_CURVE   | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------+----------------------------------------------+
 * | P2    | P2_PARAM   | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------+----------------------------------------------+
 * | Lc    | #(Payload) |                                              |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_1] | 1-byte curve identifier, from                |
 * |       |            | :cpp:type:`SE05x_ECCurve_t`                  |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_2] | 1-byte :cpp:type:`SE05x_ECCurveParam_t`      |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_3] | Bytestring containing curve parameter value. |
 * +-------+------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] curveID curve id [1:kSE05x_TAG_1]
 * @param[in] ecCurveParam ecCurveParam [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_SetECCurveParam(pSe05xSession_t session_ctx,
    SE05x_ECCurve_t curveID,
    SE05x_ECCurveParam_t ecCurveParam,
    const uint8_t *inputData,
    size_t inputDataLen);

/** Se05x_API_GetECCurveId
 *
 * Get the curve associated with an EC key.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+-----------------------------+
 * | Field   | Value      | Description                 |
 * +=========+============+=============================+
 * | CLA     | 0x80       |                             |
 * +---------+------------+-----------------------------+
 * | INS     | INS_READ   | See :cpp:type:`SE05x_INS_t` |
 * +---------+------------+-----------------------------+
 * | P1      | P1_CURVE   | See :cpp:type:`SE05x_P1_t`  |
 * +---------+------------+-----------------------------+
 * | P2      | P2_ID      | See :cpp:type:`SE05x_P2_t`  |
 * +---------+------------+-----------------------------+
 * | Lc      | #(Payload) |                             |
 * +---------+------------+-----------------------------+
 * | Payload | TLV[TAG_1] | 4-byte identifier           |
 * +---------+------------+-----------------------------+
 * | Le      | 0x00       |                             |
 * +---------+------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------------------------+
 * | Value      | Description                   |
 * +============+===============================+
 * | TLV[TAG_1] | 1-byte curve identifier (from |
 * |            | :cpp:type:`SE05x_ECCurve_t`)  |
 * +------------+-------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID object id [1:kSE05x_TAG_1]
 * @param[out] pcurveId  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_GetECCurveId(pSe05xSession_t session_ctx, uint32_t objectID, uint8_t *pcurveId);

/** Se05x_API_ReadECCurveList
 *
 * Get a list of (Weierstrass) EC curves that are instantiated.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+----------+-----------------------------+
 * | Field | Value    | Description                 |
 * +=======+==========+=============================+
 * | CLA   | 0x80     |                             |
 * +-------+----------+-----------------------------+
 * | INS   | INS_READ | See :cpp:type:`SE05x_INS_t` |
 * +-------+----------+-----------------------------+
 * | P1    | P1_CURVE | See :cpp:type:`SE05x_P1_t`  |
 * +-------+----------+-----------------------------+
 * | P2    | P2_LIST  | See :cpp:type:`SE05x_P2_t`  |
 * +-------+----------+-----------------------------+
 * | Le    | 0x00     |                             |
 * +-------+----------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------------+
 * | Value      | Description                                    |
 * +============+================================================+
 * | TLV[TAG_1] | Byte array listing all curve identifiers in    |
 * |            | :cpp:type:`SE05x_ECCurve_t` (excluding UNUSED) |
 * |            | where the curve identifier < 0x40; for each    |
 * |            | curve, a 1-byte :cpp:type:`SetIndicatorRef` is |
 * |            | returned.                                      |
 * +------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[out] curveList  [0:kSE05x_TAG_1]
 * @param[in,out] pcurveListLen Length for curveList
 */
smStatus_t Se05x_API_ReadECCurveList(pSe05xSession_t session_ctx, uint8_t *curveList, size_t *pcurveListLen);

/** Se05x_API_DeleteECCurve
 *
 * Deletes an EC curve.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------+-------------------------------+
 * | Field | Value            | Description                   |
 * +=======+==================+===============================+
 * | CLA   | 0x80             |                               |
 * +-------+------------------+-------------------------------+
 * | INS   | INS_MGMT         | See :cpp:type:`SE05x_INS_t`   |
 * +-------+------------------+-------------------------------+
 * | P1    | P1_CURVE         | See :cpp:type:`SE05x_P1_t`    |
 * +-------+------------------+-------------------------------+
 * | P2    | P2_DELETE_OBJECT | See :cpp:type:`SE05x_P2_t`    |
 * +-------+------------------+-------------------------------+
 * | Lc    | #(Payload)       |                               |
 * +-------+------------------+-------------------------------+
 * |       | TLV[TAG_1]       | 1-byte curve identifier (from |
 * |       |                  | :cpp:type:`SE05x_ECCurve_t`)  |
 * +-------+------------------+-------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] curveID curve id [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_DeleteECCurve(pSe05xSession_t session_ctx, SE05x_ECCurve_t curveID);

/** Se05x_API_CreateCryptoObject
 *
 * Creates a Crypto Object on the SE05X . Once the Crypto Object is created, it
 * is bound to the user who created the Crypto Object.
 *
 * A CryptoObject is a 2-byte value consisting of a CryptoContext in MSB and one
 * of the following in LSB:
 *
 *   * DigestMode in case CryptoContext = CC_DIGEST
 *
 *   * CipherMode in case CryptoContext = CC_CIPHER
 *
 *   * MACAlgo in case CryptoContext = CC_SIGNATURE
 *
 *   * AEADMode in case CryptoContext = CC_AEAD
 *
 * # Command to Applet
 *
 * @rst
 * +---------+---------------+-------------------------------------------+
 * | Field   | Value         | Description                               |
 * +=========+===============+===========================================+
 * | CLA     | 0x80          |                                           |
 * +---------+---------------+-------------------------------------------+
 * | INS     | INS_WRITE     | See :cpp:type:`SE05x_INS_t`               |
 * +---------+---------------+-------------------------------------------+
 * | P1      | P1_CRYPTO_OBJ | See :cpp:type:`SE05x_P1_t`                |
 * +---------+---------------+-------------------------------------------+
 * | P2      | P2_DEFAULT    | See :cpp:type:`SE05x_P2_t`                |
 * +---------+---------------+-------------------------------------------+
 * | Lc      | #(Payload)    | Payload length                            |
 * +---------+---------------+-------------------------------------------+
 * | Payload | TLV[TAG_1]    | 2-byte Crypto Object identifier           |
 * +---------+---------------+-------------------------------------------+
 * |         | TLV[TAG_2]    | 1-byte :cpp:type:`SE05x_CryptoObject_t`   |
 * +---------+---------------+-------------------------------------------+
 * |         | TLV[TAG_3]    | 1-byte Crypto Object subtype, either from |
 * |         |               | :cpp:type:`DigestModeRef`, CipherMode,    |
 * |         |               | MACAlgo (depending on TAG_2) or AEADMode. |
 * +---------+---------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+----------------------------------------------+
 * | SW          | Description                                  |
 * +=============+==============================================+
 * | SW_NO_ERROR | The file is created or updated successfully. |
 * +-------------+----------------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_1]
 * @param[in] cryptoContext cryptoContext [2:kSE05x_TAG_2]
 *
 * @param[in] subtype 1-byte Crypto Object subtype, either from
 *            DigestMode, CipherMode or MACAlgo (depending on
 *            TAG_2). [3:kSE05x_TAG_3]
 */
smStatus_t Se05x_API_CreateCryptoObject(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    SE05x_CryptoContext_t cryptoContext,
    SE05x_CryptoModeSubType_t subtype);

/** Se05x_API_ReadCryptoObjectList
 *
 * Get the list of allocated Crypto Objects indicating the identifier, the
 * CryptoContext and the sub type of the CryptoContext.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------+-----------------------------+
 * | Field | Value         | Description                 |
 * +=======+===============+=============================+
 * | CLA   | 0x80          |                             |
 * +-------+---------------+-----------------------------+
 * | INS   | INS_READ      | See :cpp:type:`SE05x_INS_t` |
 * +-------+---------------+-----------------------------+
 * | P1    | P1_CRYPTO_OBJ | See :cpp:type:`SE05x_P1_t`  |
 * +-------+---------------+-----------------------------+
 * | P2    | P2_LIST       | See :cpp:type:`SE05x_P2_t`  |
 * +-------+---------------+-----------------------------+
 * | Le    | 0x00          |                             |
 * +-------+---------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------------------------+
 * | Value      | Description                                   |
 * +============+===============================================+
 * | TLV[TAG_1] | Byte array containing a list of 2-byte Crypto |
 * |            | Object identifiers, followed by 1-byte        |
 * |            | CryptoContext and 1-byte subtype for each     |
 * |            | Crypto Object (so 4 bytes for each Crypto     |
 * |            | Object).                                      |
 * +------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[out] idlist If more ids are present [0:kSE05x_TAG_1]
 * @param[in,out] pidlistLen Length for idlist
 */
smStatus_t Se05x_API_ReadCryptoObjectList(pSe05xSession_t session_ctx, uint8_t *idlist, size_t *pidlistLen);

/** Se05x_API_DeleteCryptoObject
 *
 * Deletes a Crypto Object on the SE05X .
 *
 * Note: when a Crypto Object is deleted, the memory (as mentioned in ) is de-
 * allocated, but the transient memory is only freed when de-selecting the
 * applet!
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------------+---------------------------------+
 * | Field   | Value            | Description                     |
 * +=========+==================+=================================+
 * | CLA     | 0x80             |                                 |
 * +---------+------------------+---------------------------------+
 * | INS     | INS_MGMT         | See :cpp:type:`SE05x_INS_t`     |
 * +---------+------------------+---------------------------------+
 * | P1      | P1_CRYPTO_OBJ    | See :cpp:type:`SE05x_P1_t`      |
 * +---------+------------------+---------------------------------+
 * | P2      | P2_DELETE_OBJECT | See :cpp:type:`SE05x_P2_t`      |
 * +---------+------------------+---------------------------------+
 * | Lc      | #(Payload)       | Payload length                  |
 * +---------+------------------+---------------------------------+
 * | Payload | TLV[TAG_1]       | 2-byte Crypto Object identifier |
 * +---------+------------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+----------------------------------------------+
 * | SW          | Description                                  |
 * +=============+==============================================+
 * | SW_NO_ERROR | The file is created or updated successfully. |
 * +-------------+----------------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_DeleteCryptoObject(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID);

/** Se05x_API_ECDSASign
 *
 * The ECDSASign command signs external data using the indicated key pair or
 * private key.
 *
 * The ECSignatureAlgo indicates the ECDSA algorithm that is used, but the
 * hashing of data always must be done on the host. E.g., if ECSignatureAlgo =
 * SIG_ ECDSA_SHA256, the user must have applied SHA256 on the input data
 * already.
 *
 * The user must take care of providing the correct input length; i.e., the data
 * input length (TLV[TAG_3]) must match the digest indicated in the signature
 * algorithm (TLV[TAG_2]).
 *
 * In any case, the APDU payload must be smaller than MAX_APDU_PAYLOAD_LENGTH.
 *
 * This is performed according to the ECDSA algorithm as specified in [ANSI
 * X9.62]. The signature (a sequence of two integers 'r' and 's') as
 * returned in the response adheres to the ASN.1 DER encoded formatting rules for
 * integers.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+---------------------------------------------+
 * | Field | Value        | Description                                 |
 * +=======+==============+=============================================+
 * | CLA   | 0x80         |                                             |
 * +-------+--------------+---------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                     |
 * +-------+--------------+---------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                  |
 * +-------+--------------+---------------------------------------------+
 * | P2    | P2_SIGN      | See :cpp:type:`SE05x_P2_t`                  |
 * +-------+--------------+---------------------------------------------+
 * | Lc    | #(Payload)   |                                             |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of EC key pair or private |
 * |       |              | key.                                        |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte ECSignatureAlgo.                     |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_3]   | Byte array containing input data.           |
 * +-------+--------------+---------------------------------------------+
 * | Le    | 0x00         | Expecting ASN.1 signature                   |
 * +-------+--------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------+
 * | Value      | Description                      |
 * +============+==================================+
 * | TLV[TAG_1] | ECDSA Signature in ASN.1 format. |
 * +------------+----------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] ecSignAlgo ecSignAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] signature  [0:kSE05x_TAG_1]
 * @param[in,out] psignatureLen Length for signature
 */
smStatus_t Se05x_API_ECDSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_EdDSASign
 *
 * The EdDSASign command signs external data using the indicated key pair or
 * private key (using a Twisted Edwards curve). This is performed according to
 * the EdDSA algorithm as specified in [RFC8032].
 *
 * The input data need to be the plain data (not hashed).
 *
 * The signature as returned in the response is a 64-byte array, being the
 * concatenation of the signature r and s component (without leading zeroes for
 * sign indication).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+---------------------------------------------+
 * | Field | Value        | Description                                 |
 * +=======+==============+=============================================+
 * | CLA   | 0x80         |                                             |
 * +-------+--------------+---------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                     |
 * +-------+--------------+---------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                  |
 * +-------+--------------+---------------------------------------------+
 * | P2    | P2_SIGN      | See :cpp:type:`SE05x_P2_t`                  |
 * +-------+--------------+---------------------------------------------+
 * | Lc    | #(Payload)   |                                             |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of EC key pair or private |
 * |       |              | key.                                        |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte EDSignatureAlgo                      |
 * +-------+--------------+---------------------------------------------+
 * |       | TLV[TAG_3]   | Byte array containing plain input data.     |
 * +-------+--------------+---------------------------------------------+
 * | Le    | 0x00         | Expecting signature                         |
 * +-------+--------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------+
 * | Value      | Description                              |
 * +============+==========================================+
 * | TLV[TAG_1] | EdDSA Signature (r concatenated with s). |
 * +------------+------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] edSignAlgo edSignAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] signature  [0:kSE05x_TAG_1]
 * @param[in,out] psignatureLen Length for signature
 */
smStatus_t Se05x_API_EdDSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_ECDAASign
 *
 * The ECDAASign command signs external data using the indicated key pair or
 * private key. This is performed according to ECDAA. The generated signature is:
 *
 *   * r = random mod n
 *
 *   * s = (r + T.ds) mod n where d is the private key
 *
 * The ECDAASignatureAlgo indicates the applied algorithm.
 *
 * This APDU command should be used with a key identifier linked to
 * TPM_ECC_BN_P256 curve.
 *
 * _Note:_ The applet allows the random input to be 32 bytes of zeroes; the user
 * must take care that this is not considered as valid input. Only input in the
 * interval [1, n-1] must be considered as valid.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+------------------------------------------------+
 * | Field | Value        | Description                                    |
 * +=======+==============+================================================+
 * | CLA   | 0x80         |                                                |
 * +-------+--------------+------------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                        |
 * +-------+--------------+------------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                     |
 * +-------+--------------+------------------------------------------------+
 * | P2    | P2_SIGN      | See :cpp:type:`SE05x_P2_t`                     |
 * +-------+--------------+------------------------------------------------+
 * | Lc    | #(Payload)   |                                                |
 * +-------+--------------+------------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of EC key pair or private    |
 * |       |              | key.                                           |
 * +-------+--------------+------------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte ECDAASignatureAlgo                      |
 * +-------+--------------+------------------------------------------------+
 * |       | TLV[TAG_3]   | T = 32-byte array containing hashed input      |
 * |       |              | data.                                          |
 * +-------+--------------+------------------------------------------------+
 * |       | TLV[TAG_4]   | r = 32-byte array containing random data, must |
 * |       |              | be in the interval [1, n-1] where n is the     |
 * |       |              | order of the curve.                            |
 * +-------+--------------+------------------------------------------------+
 * | Le    | 0x00         | Expecting signature                            |
 * +-------+--------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------+
 * | Value      | Description                              |
 * +============+==========================================+
 * | TLV[TAG_1] | ECDSA Signature (r concatenated with s). |
 * +------------+------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] ecdaaSignAlgo ecdaaSignAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[in] randomData randomData [4:kSE05x_TAG_4]
 * @param[in] randomDataLen Length of randomData
 * @param[out] signature  [0:kSE05x_TAG_1]
 * @param[in,out] psignatureLen Length for signature
 */
smStatus_t Se05x_API_ECDAASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECDAASignatureAlgo_t ecdaaSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *randomData,
    size_t randomDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_ECDSAVerify
 *
 * The ECDSAVerify command verifies whether the signature is correct for a given
 * (hashed) data input using an EC public key or EC key pair's public key.
 *
 * The ECSignatureAlgo indicates the ECDSA algorithm that is used, but the
 * hashing of data must always be done on the host. E.g., if ECSignatureAlgo =
 * SIG_ ECDSA_SHA256, the user must have applied SHA256 on the input data
 * already.
 *
 * The key cannot be passed externally to the command directly. In case users
 * want to use the command to verify signatures using different public keys or
 * the public key value regularly changes, the user should create a transient key
 * object to which the key value is written and then the identifier of that
 * transient secure object can be used by this ECDSAVerify command.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+-----------------------------------------------+
 * | Field | Value        | Description                                   |
 * +=======+==============+===============================================+
 * | CLA   | 0x80         |                                               |
 * +-------+--------------+-----------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                       |
 * +-------+--------------+-----------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+--------------+-----------------------------------------------+
 * | P2    | P2_VERIFY    | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+--------------+-----------------------------------------------+
 * | Lc    | #(Payload)   |                                               |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of the key pair or public   |
 * |       |              | key.                                          |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte ECSignatureAlgo.                       |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_3]   | Byte array containing ASN.1 signature         |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_5]   | Byte array containing hashed data to compare. |
 * +-------+--------------+-----------------------------------------------+
 * | Le    | 0x03         | Expecting TLV with :cpp:type:`SE05x_Result_t` |
 * +-------+--------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------+
 * | Value      | Description                          |
 * +============+======================================+
 * | TLV[TAG_1] | Result of the signature verification |
 * |            | (:cpp:type:`SE05x_Result_t`).        |
 * +------------+--------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-----------------------------+--------------------------------------+
 * | SW                          | Description                          |
 * +=============================+======================================+
 * | SW_NO_ERROR                 | The command is handled successfully. |
 * +-----------------------------+--------------------------------------+
 * | SW_CONDITIONS_NOT_SATISFIED | Incorrect data                       |
 * +-----------------------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] ecSignAlgo ecSignAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[in] signature signature [4:kSE05x_TAG_5]
 * @param[in] signatureLen Length of signature
 * @param[out] presult  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_ECDSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_ECSignatureAlgo_t ecSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult);

/** Se05x_API_EdDSAVerify
 *
 * The EdDSAVerify command verifies whether the signature is correct for a given
 * data input (hashed using SHA512) using an EC public key or EC key pair's
 * public key. The signature needs to be given as concatenation of r and s.
 *
 * The data needs to be compared with the plain message without being hashed.
 *
 * _Note_ : See chapter 7 for correct byte order as both r and s need to be byte
 * swapped.
 *
 * This is performed according to the EdDSA algorithm as specified in [RFC8032].
 *
 * The key cannot be passed externally to the command directly. In case users
 * want to use the command to verify signatures using different public keys or
 * the public key value regularly changes, the user should create a transient key
 * object to which the key value is written and then the identifier of that
 * transient secure object can be used by this EdDSAVerify command.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+-----------------------------------------------+
 * | Field | Value        | Description                                   |
 * +=======+==============+===============================================+
 * | CLA   | 0x80         |                                               |
 * +-------+--------------+-----------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                       |
 * +-------+--------------+-----------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+--------------+-----------------------------------------------+
 * | P2    | P2_VERIFY    | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+--------------+-----------------------------------------------+
 * | Lc    | #(Payload)   |                                               |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of the key pair or public   |
 * |       |              | key.                                          |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte :cpp:type:`EDSignatureAlgoRef`.        |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_3]   | 64-byte array containing the signature        |
 * |       |              | (concatenation of r and s).                   |
 * +-------+--------------+-----------------------------------------------+
 * |       | TLV[TAG_5]   | Byte array containing plain data to compare.  |
 * +-------+--------------+-----------------------------------------------+
 * | Le    | 0x03         | Expecting TLV with :cpp:type:`SE05x_Result_t` |
 * +-------+--------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------+
 * | Value      | Description                          |
 * +============+======================================+
 * | TLV[TAG_1] | Result of the signature verification |
 * |            | (:cpp:type:`SE05x_Result_t`).        |
 * +------------+--------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-----------------------------+--------------------------------------+
 * | SW                          | Description                          |
 * +=============================+======================================+
 * | SW_NO_ERROR                 | The command is handled successfully. |
 * +-----------------------------+--------------------------------------+
 * | SW_CONDITIONS_NOT_SATISFIED | Incorrect data                       |
 * +-----------------------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] edSignAlgo edSignAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[in] signature signature [4:kSE05x_TAG_5]
 * @param[in] signatureLen Length of signature
 * @param[out] presult  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_EdDSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_EDSignatureAlgo_t edSignAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult);

/** Se05x_API_ECDHGenerateSharedSecret
 *
 * The ECDHGenerateSharedSecret command generates a shared secret ECC point on
 * the curve using an EC private key on SE05X and an external public key provided
 * by the caller. The output shared secret is returned to the caller.
 *
 * All curves from ECCurve are supported, except ECC_ED_25519.
 *
 * Note that ECDHGenerateSharedSecret commands with EC keys using curve
 * ID_ECC_MONT_DH_25519 or ID_ECC_MONT_DH_448 cause NVM write operations for each
 * call. This is not the case for the other curves.
 *
 * When CONFIG_FIPS_MODE_DISABLED is not set, this function will always return
 * SW_CONDTIONS_NOT_SATISFIED.
 *
 * The shared secret can only be received when the Secure Object containing the
 * key pair or private key (TLV[TAG_1]) does not contain the policy
 * POLICY_OBJ_FORBID_DERIVED_OUTPUT. If that is the case, the user must provide
 * TLV[TAG_7} to store the shared secret in an HMACKey object. The user is
 * responsible to assign the correct size of the HMACKey object: this must equal
 * the size of the shared secret exactly.
 *
 * On applet 4.4.0, the policy POLICY_OBJ_FORBID_DERIVED_OUTPUT is not yet
 * verified for this function. It will always be allowed.
 *
 * # Command to Applet
 *
 * @rst
 * +------------+------------------------------+----------------------------------------------+
 * | Field      | Value                        | Description                                  |
 * +============+==============================+==============================================+
 * | CLA        | 0x80                         |                                              |
 * +------------+------------------------------+----------------------------------------------+
 * | INS        | INS_CRYPTO                   | :cpp:type:`SE05x_INS_t`                      |
 * +------------+------------------------------+----------------------------------------------+
 * | P1         | P1_EC                        | See :cpp:type:`SE05x_P1_t`                   |
 * +------------+------------------------------+----------------------------------------------+
 * | P2         | P2_DH                        | See :cpp:type:`SE05x_P2_t`                   |
 * +------------+------------------------------+----------------------------------------------+
 * | Lc         | #(Payload)                   |                                              |
 * +------------+------------------------------+----------------------------------------------+
 * | Payload    | TLV[TAG_1]                   | 4-byte identifier of the key pair or private |
 * |            |                              | key.                                         |
 * +------------+------------------------------+----------------------------------------------+
 * | TLV[TAG_2] | External public key (see     |                                              |
 * |            | :cpp:type:`ECKeyRef`).       |                                              |
 * +------------+------------------------------+----------------------------------------------+
 * | TLV[TAG_7] | 4-byte HMACKey identifier to |                                              |
 * |            | store output.    [Optional]  |                                              |
 * +------------+------------------------------+----------------------------------------------+
 * | Le         | 0x00                         | Expected shared secret length.               |
 * +------------+------------------------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------------------+
 * | Value      | Description                                  |
 * +============+==============================================+
 * | TLV[TAG_1] | The returned shared secret.    [Conditional: |
 * |            | only when the input does not contain         |
 * |            | TLV[TAG_7].}                                 |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] pubKey pubKey [2:kSE05x_TAG_2]
 * @param[in] pubKeyLen Length of pubKey
 * @param[out] sharedSecret  [0:kSE05x_TAG_1]
 * @param[in,out] psharedSecretLen Length for sharedSecret
 */
smStatus_t Se05x_API_ECDHGenerateSharedSecret(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    uint8_t *sharedSecret,
    size_t *psharedSecretLen);

/** Se05x_API_RSASign
 *
 * The RSASign command signs the input message using an RSA private key.
 *
 * @rst
 * +----------------------+-------+----------------------------+
 * | Name                 | Value | Description                |
 * +======================+=======+============================+
 * | RSA_SHA1_PKCS1_PSS   | 0x15  | RFC8017: RSASSA-PSS        |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA224_PKCS1_PSS | 0x2B  | RFC8017: RSASSA-PSS        |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA256_PKCS1_PSS | 0x2C  | RFC8017: RSASSA-PSS        |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA384_PKCS1_PSS | 0x2D  | RFC8017: RSASSA-PSS        |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA512_PKCS1_PSS | 0x2E  | RFC8017: RSASSA-PSS        |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA1_PKCS1       | 0x0A  | RFC8017: RSASSA-PKCS1-v1_5 |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA_224_PKCS1    | 0x27  | RFC8017: RSASSA-PKCS1-v1_5 |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA_256_PKCS1    | 0x28  | RFC8017: RSASSA-PKCS1-v1_5 |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA_384_PKCS1    | 0x29  | RFC8017: RSASSA-PKCS1-v1_5 |
 * +----------------------+-------+----------------------------+
 * | RSA_SHA_512_PKCS1    | 0x2A  | RFC8017: RSASSA-PKCS1-v1_5 |
 * +----------------------+-------+----------------------------+
 * @endrst
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+----------------------------------------------+
 * | Field | Value        | Description                                  |
 * +=======+==============+==============================================+
 * | CLA   | 0x80         |                                              |
 * +-------+--------------+----------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                      |
 * +-------+--------------+----------------------------------------------+
 * | P1    | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+--------------+----------------------------------------------+
 * | P2    | P2_SIGN      | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+--------------+----------------------------------------------+
 * | Lc    | #(Payload)   |                                              |
 * +-------+--------------+----------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte identifier of the key pair or private |
 * |       |              | key.                                         |
 * +-------+--------------+----------------------------------------------+
 * |       | TLV[TAG_2]   | 1-byte :cpp:type:`SE05x_RSASignAlgo_t`       |
 * +-------+--------------+----------------------------------------------+
 * |       | TLV[TAG_3]   | Byte array containing input data.            |
 * +-------+--------------+----------------------------------------------+
 * | Le    | 0x00         | Expecting ASN.1 signature.                   |
 * +-------+--------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------+
 * | Value      | Description                    |
 * +============+================================+
 * | TLV[TAG_1] | RSA signature in ASN.1 format. |
 * +------------+--------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] rsaSigningAlgo rsaSigningAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] signature  [0:kSE05x_TAG_1]
 * @param[in,out] psignatureLen Length for signature
 */
smStatus_t Se05x_API_RSASign(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSASignatureAlgo_t rsaSigningAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *signature,
    size_t *psignatureLen);

/** Se05x_API_RSAVerify
 *
 * The RSAVerify command verifies the given signature and returns the result.
 *
 * The key cannot be passed externally to the command directly. In case users
 * want to use the command to verify signatures using different public keys or
 * the public key value regularly changes, the user should create a transient key
 * object to which the key value is written and then the identifier of that
 * transient secure object can be used by this RSAVerify command.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+--------------+---------------------------------------------+
 * | Field   | Value        | Description                                 |
 * +=========+==============+=============================================+
 * | CLA     | 0x80         |                                             |
 * +---------+--------------+---------------------------------------------+
 * | INS     | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                     |
 * +---------+--------------+---------------------------------------------+
 * | P1      | P1_SIGNATURE | See :cpp:type:`SE05x_P1_t`                  |
 * +---------+--------------+---------------------------------------------+
 * | P2      | P2_VERIFY    | See :cpp:type:`SE05x_P2_t`                  |
 * +---------+--------------+---------------------------------------------+
 * | Lc      | #(Payload)   |                                             |
 * +---------+--------------+---------------------------------------------+
 * | Payload |              |                                             |
 * +---------+--------------+---------------------------------------------+
 * |         | TLV[TAG_1]   | 4-byte identifier of the key pair or public |
 * |         |              | key.                                        |
 * +---------+--------------+---------------------------------------------+
 * |         | TLV[TAG_2]   | 1-byte :cpp:type:`SE05x_RSASignAlgo_t`      |
 * +---------+--------------+---------------------------------------------+
 * |         | TLV[TAG_3]   | Byte array containing data to be verified.  |
 * +---------+--------------+---------------------------------------------+
 * |         | TLV[TAG_5]   | Byte array containing ASN.1 signature.      |
 * +---------+--------------+---------------------------------------------+
 * | Le      | 0x03         | Expecting Result in TLV                     |
 * +---------+--------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------+
 * | Value      | Description                              |
 * +============+==========================================+
 * | TLV[TAG_1] | :cpp:type:`SE05x_Result_t`: Verification |
 * |            | result                                   |
 * +------------+------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] rsaSigningAlgo rsaSigningAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[in] signature signature [4:kSE05x_TAG_5]
 * @param[in] signatureLen Length of signature
 * @param[out] presult  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_RSAVerify(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSASignatureAlgo_t rsaSigningAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *signature,
    size_t signatureLen,
    SE05x_Result_t *presult);

/** Se05x_API_RSAEncrypt
 *
 * The RSAEncrypt command encrypts data.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+--------------------+----------------------------------------------+
 * | Field   | Value              | Description                                  |
 * +=========+====================+==============================================+
 * | CLA     | 0x80               |                                              |
 * +---------+--------------------+----------------------------------------------+
 * | INS     | INS_CRYPTO         | :cpp:type:`SE05x_INS_t`                      |
 * +---------+--------------------+----------------------------------------------+
 * | P1      | P1_RSA             | See :cpp:type:`SE05x_P1_t`                   |
 * +---------+--------------------+----------------------------------------------+
 * | P2      | P2_ENCRYPT_ONESHOT | See :cpp:type:`SE05x_P2_t`                   |
 * +---------+--------------------+----------------------------------------------+
 * | Lc      | #(Payload)         |                                              |
 * +---------+--------------------+----------------------------------------------+
 * | Payload | TLV[TAG_1]         | 4-byte identifier of the key pair or public  |
 * |         |                    | key.                                         |
 * +---------+--------------------+----------------------------------------------+
 * |         | TLV[TAG_2]         | 1-byte :cpp:type:`SE05x_RSAEncryptionAlgo_t` |
 * +---------+--------------------+----------------------------------------------+
 * |         | TLV[TAG_3]         | Byte array containing data to be encrypted.  |
 * +---------+--------------------+----------------------------------------------+
 * | Le      | 0x00               | Expected TLV with encrypted data.            |
 * +---------+--------------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------+
 * | Value      | Description    |
 * +============+================+
 * | TLV[TAG_1] | Encrypted data |
 * +------------+----------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] rsaEncryptionAlgo rsaEncryptionAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] encryptedData  [0:kSE05x_TAG_1]
 * @param[in,out] pencryptedDataLen Length for encryptedData
 */
smStatus_t Se05x_API_RSAEncrypt(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *encryptedData,
    size_t *pencryptedDataLen);

/** Se05x_API_RSADecrypt
 *
 * The RSADecrypt command decrypts data.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+--------------------+----------------------------------------------+
 * | Field   | Value              | Description                                  |
 * +=========+====================+==============================================+
 * | CLA     | 0x80               |                                              |
 * +---------+--------------------+----------------------------------------------+
 * | INS     | INS_CRYPTO         | :cpp:type:`SE05x_INS_t`                      |
 * +---------+--------------------+----------------------------------------------+
 * | P1      | P1_RSA             | See :cpp:type:`SE05x_P1_t`                   |
 * +---------+--------------------+----------------------------------------------+
 * | P2      | P2_DECRYPT_ONESHOT | See :cpp:type:`SE05x_P2_t`                   |
 * +---------+--------------------+----------------------------------------------+
 * | Lc      | #(Payload)         |                                              |
 * +---------+--------------------+----------------------------------------------+
 * | Payload | TLV[TAG_1]         | 4-byte identifier of the key pair or private |
 * |         |                    | key.                                         |
 * +---------+--------------------+----------------------------------------------+
 * |         | TLV[TAG_2]         | 1-byte :cpp:type:`SE05x_RSAEncryptionAlgo_t` |
 * +---------+--------------------+----------------------------------------------+
 * |         | TLV[TAG_3]         | Byte array containing data to be decrypted.  |
 * +---------+--------------------+----------------------------------------------+
 * | Le      | 0x00               | Expected TLV with decrypted data.            |
 * +---------+--------------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------+
 * | Value      | Description    |
 * +============+================+
 * | TLV[TAG_1] | Encrypted data |
 * +------------+----------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] rsaEncryptionAlgo rsaEncryptionAlgo [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] decryptedData  [0:kSE05x_TAG_1]
 * @param[in,out] pdecryptedDataLen Length for decryptedData
 */
smStatus_t Se05x_API_RSADecrypt(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_RSAEncryptionAlgo_t rsaEncryptionAlgo,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *decryptedData,
    size_t *pdecryptedDataLen);

/** Se05x_API_CipherInit
 *
 * Initialize a symmetric encryption or decryption. The Crypto Object keeps the
 * state of the cipher operation until it's finalized or deleted. Once the
 * CipherFinal function is executed successfully, the Crypto Object state returns
 * to the state immediately after the previous CipherInit function.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+--------------------------+--------------------------------------------+
 * | Field   | Value                    | Description                                |
 * +=========+==========================+============================================+
 * | CLA     | 0x80                     |                                            |
 * +---------+--------------------------+--------------------------------------------+
 * | INS     | INS_CRYPTO               | :cpp:type:`SE05x_INS_t`                    |
 * +---------+--------------------------+--------------------------------------------+
 * | P1      | P1_CIPHER                | See :cpp:type:`SE05x_P1_t`                 |
 * +---------+--------------------------+--------------------------------------------+
 * | P2      | P2_ENCRYPT or P2_DECRYPT | See :cpp:type:`SE05x_P2_t`                 |
 * +---------+--------------------------+--------------------------------------------+
 * | Lc      | #(Payload)               |                                            |
 * +---------+--------------------------+--------------------------------------------+
 * | Payload | TLV[TAG_1]               | 4-byte identifier of the key object.       |
 * +---------+--------------------------+--------------------------------------------+
 * |         | TLV[TAG_2]               | 2-byte Crypto Object identifier            |
 * +---------+--------------------------+--------------------------------------------+
 * |         | TLV[TAG_4]               | Initialization Vector   [Optional]         |
 * |         |                          | [Conditional:  only when the Crypto Object |
 * |         |                          | type equals  CC_CIPHER and subtype is not  |
 * |         |                          | including ECB]                             |
 * +---------+--------------------------+--------------------------------------------+
 * | Le      | -                        |                                            |
 * +---------+--------------------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] cryptoObjectID cryptoObjectID [2:kSE05x_TAG_2]
 * @param[in] IV IV [3:kSE05x_TAG_4]
 * @param[in] IVLen Length of IV
 * @param[in] operation See @ref SE05x_Cipher_Oper_t
 */
smStatus_t Se05x_API_CipherInit(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *IV,
    size_t IVLen,
    const SE05x_Cipher_Oper_t operation);

/** Se05x_API_CipherUpdate
 *
 * Update a cipher context.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +------------+----------------------------------+---------------------------------+
 * | Field      | Value                            | Description                     |
 * +============+==================================+=================================+
 * | CLA        | 0x80                             |                                 |
 * +------------+----------------------------------+---------------------------------+
 * | INS        | INS_CRYPTO                       | :cpp:type:`SE05x_INS_t`         |
 * +------------+----------------------------------+---------------------------------+
 * | P1         | P1_CIPHER                        | See :cpp:type:`SE05x_P1_t`      |
 * +------------+----------------------------------+---------------------------------+
 * | P2         | P2_UPDATE                        | See :cpp:type:`SE05x_P2_t`      |
 * +------------+----------------------------------+---------------------------------+
 * | Lc         | #(Payload)                       |                                 |
 * +------------+----------------------------------+---------------------------------+
 * | Payload    | TLV[TAG_2]                       | 2-byte Crypto Object identifier |
 * +------------+----------------------------------+---------------------------------+
 * | TLV[TAG_3] | Byte array containing input data |                                 |
 * +------------+----------------------------------+---------------------------------+
 * | Le         | 0x00                             | Expecting returned data.        |
 * +------------+----------------------------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------+
 * | Value      | Description |
 * +============+=============+
 * | TLV[TAG_1] | Output data |
 * +------------+-------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_2]
 * @param[in] inputData inputData [2:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] outputData  [0:kSE05x_TAG_1]
 * @param[in,out] poutputDataLen Length for outputData
 */
smStatus_t Se05x_API_CipherUpdate(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen);

/** Se05x_API_CipherFinal
 *
 * Finish a sequence of cipher operations.
 *
 * # Command to Applet
 *
 * @rst
 * +------------+------------+---------------------------------+
 * | Field      | Value      | Description                     |
 * +============+============+=================================+
 * | CLA        | 0x80       |                                 |
 * +------------+------------+---------------------------------+
 * | INS        | INS_CRYPTO | :cpp:type:`SE05x_INS_t`         |
 * +------------+------------+---------------------------------+
 * | P1         | P1_CIPHER  | See :cpp:type:`SE05x_P1_t`      |
 * +------------+------------+---------------------------------+
 * | P2         | P2_FINAL   | See :cpp:type:`SE05x_P2_t`      |
 * +------------+------------+---------------------------------+
 * | Lc         | #(Payload) |                                 |
 * +------------+------------+---------------------------------+
 * | Payload    | TLV[TAG_2] | 2-byte Crypto Object identifier |
 * +------------+------------+---------------------------------+
 * | TLV[TAG_3] | Input data |                                 |
 * +------------+------------+---------------------------------+
 * | Le         | 0x00       | Expected returned data.         |
 * +------------+------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------+
 * | Value      | Description |
 * +============+=============+
 * | TLV[TAG_1] | Output data |
 * +------------+-------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_2]
 * @param[in] inputData inputData [2:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] outputData  [0:kSE05x_TAG_1]
 * @param[in,out] poutputDataLen Length for outputData
 */
smStatus_t Se05x_API_CipherFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen);

/**
 * @brief      Se05x_API_CipherOneShot
 *
 * Encrypt or decrypt data in one shot mode.
 *
 * The key object must be either an AES key or DES key.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+-----------------------+------------------------------------------------+
 * | Field   | Value                 | Description                                    |
 * +=========+=======================+================================================+
 * | CLA     | 0x80                  |                                                |
 * +---------+-----------------------+------------------------------------------------+
 * | INS     | INS_CRYPTO            | :cpp:type:`SE05x_INS_t`                        |
 * +---------+-----------------------+------------------------------------------------+
 * | P1      | P1_CIPHER             | See :cpp:type:`SE05x_P1_t`                     |
 * +---------+-----------------------+------------------------------------------------+
 * | P2      | P2_ENCRYPT_ONESHOT or | See :cpp:type:`SE05x_P2_t`                     |
 * |         | P2_DECRYPT_ONESHOT    |                                                |
 * +---------+-----------------------+------------------------------------------------+
 * | Lc      | #(Payload)            |                                                |
 * +---------+-----------------------+------------------------------------------------+
 * | Payload | TLV[TAG_1]            | 4-byte identifier of the key object.           |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_2]            | 1-byte CipherMode                              |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_3]            | Byte array containing input data.              |
 * +---------+-----------------------+------------------------------------------------+
 * |         | TLV[TAG_4]            | Byte array containing an initialization        |
 * |         |                       | vector.   [Optional]   [Conditional: only when |
 * |         |                       | the Crypto Object type equals CC_CIPHER and    |
 * |         |                       | subtype is not including ECB]                  |
 * +---------+-----------------------+------------------------------------------------+
 * | Le      | 0x00                  | Expecting return data.                         |
 * +---------+-----------------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------+
 * | Value      | Description |
 * +============+=============+
 * | TLV[TAG_1] | Output data |
 * +------------+-------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in]  session_ctx     The session context
 * @param[in]  objectID        The object id
 * @param[in]  cipherMode      The cipher mode
 * @param[in]  inputData       The input data
 * @param[in]  inputDataLen    The input data length
 * @param[in]  IV              Initial vector
 * @param[in]  IVLen           The iv length
 * @param      outputData      The output data
 * @param      poutputDataLen  The poutput data length
 * @param[in]  operation       The operation
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_CipherOneShot(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CipherMode_t cipherMode,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *IV,
    size_t IVLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_Cipher_Oper_OneShot_t operation);

/** Se05x_API_MACInit
 *
 * Initiate a MAC operation. The state of the MAC operation is kept in the Crypto
 * Object until it's finalized or deleted.
 *
 * The 4-byte identifier of the key must refer to an AESKey, DESKey or HMACKey.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +---------+----------------------------+-----------------------------------+
 * | Field   | Value                      | Description                       |
 * +=========+============================+===================================+
 * | CLA     | 0x80                       |                                   |
 * +---------+----------------------------+-----------------------------------+
 * | INS     | INS_CRYPTO                 | :cpp:type:`SE05x_INS_t`           |
 * +---------+----------------------------+-----------------------------------+
 * | P1      | P1_MAC                     | See :cpp:type:`SE05x_P1_t`        |
 * +---------+----------------------------+-----------------------------------+
 * | P2      | P2_GENERATE or P2_VALIDATE | See :cpp:type:`SE05x_P2_t`        |
 * +---------+----------------------------+-----------------------------------+
 * | Lc      | #(Payload)                 |                                   |
 * +---------+----------------------------+-----------------------------------+
 * | Payload | TLV[TAG_1]                 | 4-byte identifier of the MAC key. |
 * +---------+----------------------------+-----------------------------------+
 * |         | TLV[TAG_2]                 | 2-byte Crypto Object identifier   |
 * +---------+----------------------------+-----------------------------------+
 * | Le      | 0x00                       |                                   |
 * +---------+----------------------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] cryptoObjectID cryptoObjectID [2:kSE05x_TAG_2]
 * @param[in] mac_oper The Operation
 */
smStatus_t Se05x_API_MACInit(pSe05xSession_t session_ctx,
    uint32_t objectID,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const SE05x_Mac_Oper_t mac_oper);

/** Se05x_API_MACUpdate
 *
 * Update MAC
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+-------------------------------------------+
 * | Field   | Value      | Description                               |
 * +=========+============+===========================================+
 * | CLA     | 0x80       |                                           |
 * +---------+------------+-------------------------------------------+
 * | INS     | INS_CRYPTO | :cpp:type:`SE05x_INS_t`                   |
 * +---------+------------+-------------------------------------------+
 * | P1      | P1_MAC     | See :cpp:type:`SE05x_P1_t`                |
 * +---------+------------+-------------------------------------------+
 * | P2      | P2_UPDATE  | See :cpp:type:`SE05x_P2_t`                |
 * +---------+------------+-------------------------------------------+
 * | Lc      | #(Payload) |                                           |
 * +---------+------------+-------------------------------------------+
 * | Payload | TLV[TAG_1] | Byte array containing data to be taken as |
 * |         |            | input to MAC.                             |
 * +---------+------------+-------------------------------------------+
 * |         | TLV[TAG_2] | 2-byte Crypto Object identifier           |
 * +---------+------------+-------------------------------------------+
 * | Le      | -          |                                           |
 * +---------+------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] inputData inputData [1:kSE05x_TAG_1]
 * @param[in] inputDataLen Length of inputData
 * @param[in] cryptoObjectID cryptoObjectID [2:kSE05x_TAG_2]
 */
smStatus_t Se05x_API_MACUpdate(
    pSe05xSession_t session_ctx, const uint8_t *inputData, size_t inputDataLen, SE05x_CryptoObjectID_t cryptoObjectID);

/** Se05x_API_MACFinal
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------+--------------------------------------------+
 * | Field   | Value      | Description                                |
 * +=========+============+============================================+
 * | CLA     | 0x80       |                                            |
 * +---------+------------+--------------------------------------------+
 * | INS     | INS_CRYPTO | :cpp:type:`SE05x_INS_t`                    |
 * +---------+------------+--------------------------------------------+
 * | P1      | P1_MAC     | See :cpp:type:`SE05x_P1_t`                 |
 * +---------+------------+--------------------------------------------+
 * | P2      | P2_FINAL   | See :cpp:type:`SE05x_P2_t`                 |
 * +---------+------------+--------------------------------------------+
 * | Payload | TLV[TAG_1] | Byte array containing data to be taken as  |
 * |         |            | input to MAC.                              |
 * +---------+------------+--------------------------------------------+
 * |         | TLV[TAG_2] | 2-byte Crypto Object identifier            |
 * +---------+------------+--------------------------------------------+
 * |         | TLV[TAG_3] | Byte array containing MAC to validate.     |
 * |         |            | [Conditional: only applicable the crypto   |
 * |         |            | object is set for validating (MACInit P2 = |
 * |         |            | P2_VALIDATE)]                              |
 * +---------+------------+--------------------------------------------+
 * | Le      | 0x00       | Expecting MAC or result.                   |
 * +---------+------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------------------------+
 * | Value      | Description                                   |
 * +============+===============================================+
 * | TLV[TAG_1] | MAC value (when MACInit had P2 = P2_GENERATE) |
 * |            | or :cpp:type:`SE05x_Result_t` (when MACInit   |
 * |            | had P2 = P2_VERIFY).                          |
 * +------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] inputData inputData [1:kSE05x_TAG_1]
 * @param[in] inputDataLen Length of inputData
 * @param[in] cryptoObjectID cryptoObjectID [2:kSE05x_TAG_2]
 * @param[in] macValidateData macValidateData [3:kSE05x_TAG_3]
 * @param[in] macValidateDataLen Length of macValidateData
 * @param[out] macValue  [0:kSE05x_TAG_1]
 * @param[in,out] pmacValueLen Length for macValue
 */
smStatus_t Se05x_API_MACFinal(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *macValidateData,
    size_t macValidateDataLen,
    uint8_t *macValue,
    size_t *pmacValueLen);

/** Se05x_API_MACOneShot_G
 *
 * Generate.  See @ref Se05x_API_MACOneShot_V for Verfiication.
 *
 * Performs a MAC operation in one shot (without keeping state).
 *
 * The 4-byte identifier of the key must refer to an AESKey, DESKey or HMACKey.
 *
 * # Command to Applet
 *
 * @rst
 * +---------+------------------------+---------------------------------------------+
 * | Field   | Value                  | Description                                 |
 * +=========+========================+=============================================+
 * | CLA     | 0x80                   |                                             |
 * +---------+------------------------+---------------------------------------------+
 * | INS     | INS_CRYPTO             | :cpp:type:`SE05x_INS_t`                     |
 * +---------+------------------------+---------------------------------------------+
 * | P1      | P1_MAC                 | See :cpp:type:`SE05x_P1_t`                  |
 * +---------+------------------------+---------------------------------------------+
 * | P2      | P2_GENERATE_ONESHOT or | See :cpp:type:`SE05x_P2_t`                  |
 * |         | P2_VALIDATE_ONESHOT    |                                             |
 * +---------+------------------------+---------------------------------------------+
 * | Lc      | #(Payload)             |                                             |
 * +---------+------------------------+---------------------------------------------+
 * | Payload | TLV[TAG_1]             | 4-byte identifier of the key object.        |
 * +---------+------------------------+---------------------------------------------+
 * |         | TLV[TAG_2]             | 1-byte :cpp:type:`MACAlgoRef`               |
 * +---------+------------------------+---------------------------------------------+
 * |         | TLV[TAG_3]             | Byte array containing data to be taken as   |
 * |         |                        | input to MAC.                               |
 * +---------+------------------------+---------------------------------------------+
 * |         | TLV[TAG_5]             | MAC to verify (when P2=P2_VALIDATE_ONESHOT) |
 * +---------+------------------------+---------------------------------------------+
 * | Le      | 0x00                   | Expecting MAC or Result.                    |
 * +---------+------------------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+---------------------------------------+
 * | Value      | Description                           |
 * +============+=======================================+
 * | TLV[TAG_1] | MAC value (P2=P2_GENERATE_ONESHOT) or |
 * |            | :cpp:type:`SE05x_Result_t` (when      |
 * |            | p2=P2_VALIDATE_ONESHOT).              |
 * +------------+---------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] macOperation macOperation [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] macValue  [0:kSE05x_TAG_1]
 * @param[in,out] pmacValueLen Length for macValue
 */
smStatus_t Se05x_API_MACOneShot_G(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t macOperation,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *macValue,
    size_t *pmacValueLen);

/** Se05x_API_MACOneShot_V
 *
 * Validate.  See @ref Se05x_API_MACOneShot_G for Generation.
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] macOperation macOperation [2:kSE05x_TAG_2]
 * @param[in] inputData inputData [3:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[in] MAC MAC to verify (when P2=P2_VALIDATE_ONESHOT) [4:kSE05x_TAG_5]
 * @param[in] MACLen Length of MAC
 * @param[out] macValue  [0:kSE05x_TAG_1]
 * @param[in,out] pmacValueLen Length for macValue
 */
smStatus_t Se05x_API_MACOneShot_V(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t macOperation,
    const uint8_t *inputData,
    size_t inputDataLen,
    const uint8_t *MAC,
    size_t MACLen,
    uint8_t *macValue,
    size_t *pmacValueLen);

/** Se05x_API_HKDF
 *
 * Note that this KDF is equal to the KDF in Feedback Mode described in [NIST
 * SP800-108] with the PRF being HMAC with SHA256 and with an 8-bit counter at
 * the end of the iteration variable.
 *
 * The full HKDF algorithm is executed, i.e. Extract-And-Expand.
 *
 * The caller must provide a salt length (0 up to 64 bytes). If salt length
 * equals 0 or salt is not provided as input, the default salt will be used.
 *
 * The output of the HKDF functions can be either:
 *
 *   * send back to the caller => _precondition_ : none of the input Secure Objects -if present- shall have a policy POLICY_OBJ_FORBID_DERIVED_OUTPUT set.
 *
 *   * be stored in a Secure Object => _precondition_ : the Secure Object must be created upfront and the size must exactly match the expected length.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +------------+--------------------------------+-----------------------------------+
 * | Field      | Value                          | Description                       |
 * +============+================================+===================================+
 * | CLA        | 0x80                           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | INS        | INS_CRYPTO                     | :cpp:type:`SE05x_INS_t`           |
 * +------------+--------------------------------+-----------------------------------+
 * | P1         | P1_DEFAULT                     | See :cpp:type:`SE05x_P1_t`        |
 * +------------+--------------------------------+-----------------------------------+
 * | P2         | P2_HKDF                        | See :cpp:type:`SE05x_P2_t`        |
 * +------------+--------------------------------+-----------------------------------+
 * | Lc         | #(Payload)                     |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | Payload    | TLV[TAG_1]                     | 4-byte HMACKey identifier (= IKM) |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_2] | 1-byte DigestMode (except      |                                   |
 * |            | DIGEST_NO_HASH)                |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_3] | Byte array (0-64 bytes)        |                                   |
 * |            | containing salt.   [Optional]  |                                   |
 * |            | [Conditional: only when        |                                   |
 * |            | TLV[TAG_6] is absent.]         |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_4] | Info: The context and          |                                   |
 * |            | information to apply (1 to 80  |                                   |
 * |            | bytes).   [Optional]           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_5] | 2-byte requested length (L): 1 |                                   |
 * |            | up to MAX_APDU_PAYLOAD_LENGTH  |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_6] | 4-byte HMACKey identifier      |                                   |
 * |            | containing salt.   [Optional]  |                                   |
 * |            | [Conditional: only when        |                                   |
 * |            | TLV[TAG_3] is absent]          |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_7] | 4-byte HMACKey identifier to   |                                   |
 * |            | store output.   [Optional]     |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | Le         | 0x00                           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * @endrst
 *
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_1] | HKDF output.   [Conditional: only when the |
 * |            | input does not contain TLV[TAG-7]]         |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+------------------------------------+
 * | SW          | Description                        |
 * +=============+====================================+
 * | SW_NO_ERROR | The HKDF is executed successfully. |
 * +-------------+------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] hmacID hmacID [1:kSE05x_TAG_1]
 * @param[in] digestMode digestMode [2:kSE05x_TAG_2]
 * @param[in] salt salt [3:kSE05x_TAG_3]
 * @param[in] saltLen Length of salt
 * @param[in] info info [4:kSE05x_TAG_4]
 * @param[in] infoLen Length of info
 * @param[in] deriveDataLen 2-byte requested length (L) [5:kSE05x_TAG_5]
 * @param[out] hkdfOuput  [0:kSE05x_TAG_1]
 * @param[in,out] phkdfOuputLen Length for hkdfOuput
 */
smStatus_t Se05x_API_HKDF(pSe05xSession_t session_ctx,
    uint32_t hmacID,
    SE05x_DigestMode_t digestMode,
    const uint8_t *salt,
    size_t saltLen,
    const uint8_t *info,
    size_t infoLen,
    uint16_t deriveDataLen,
    uint8_t *hkdfOuput,
    size_t *phkdfOuputLen);

/** Se05x_API_HKDF_Extended
 *
 * Only step 2 of the algorithm is executed, i.e. Expand only.
 *
 * Using an IV as input parameter results in a FIPS compliant SP800-108 KDF in
 * Feedback Mode where K[0] is the provided IV. This KDF is then using a 8-bit
 * counter, AFTER_FIXED counter location.
 *
 * # Command to Applet
 *
 * @rst
 * +------------+--------------------------------+-----------------------------------+
 * | Field      | Value                          | Description                       |
 * +============+================================+===================================+
 * | CLA        | 0x80                           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | INS        | INS_CRYPTO                     | :cpp:type:`SE05x_INS_t`           |
 * +------------+--------------------------------+-----------------------------------+
 * | P1         | P1_DEFAULT                     | See :cpp:type:`SE05x_P1_t`        |
 * +------------+--------------------------------+-----------------------------------+
 * | P2         | P2_HKDF_EXPAND_ONLY            | See :cpp:type:`SE05x_P2_t`        |
 * +------------+--------------------------------+-----------------------------------+
 * | Lc         | #(Payload)                     |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | Payload    | TLV[TAG_1]                     | 4-byte HMACKey identifier (= PRK) |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_2] | 1-byte DigestMode (except      |                                   |
 * |            | DIGEST_NO_HASH)                |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_3] | Byte array (0-64 bytes)        |                                   |
 * |            | containing IV.    [Optional]   |                                   |
 * |            | [Conditional: only when        |                                   |
 * |            | TLV[TAG_6] is absent.]         |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_4] | Info: The context and          |                                   |
 * |            | information to apply (1 to 80  |                                   |
 * |            | bytes).   [Optional]           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_5] | 2-byte requested length (L): 1 |                                   |
 * |            | up to MAX_APDU_PAYLOAD_LENGTH  |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_6] | 4-byte HMACKey identifier      |                                   |
 * |            | containing IV.    [Optional]   |                                   |
 * |            | [Conditional: only when        |                                   |
 * |            | TLV[TAG_3] is absent]          |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | TLV[TAG_7] | 4-byte HMACKey identifier to   |                                   |
 * |            | store output.   [Optional]     |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * | Le         | 0x00                           |                                   |
 * +------------+--------------------------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------------+
 * | Value      | Description                                |
 * +============+============================================+
 * | TLV[TAG_1] | HKDF output.   [Conditional: only when the |
 * |            | input does not contain TLV[TAG-7]]         |
 * +------------+--------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+------------------------------------+
 * | SW          | Description                        |
 * +=============+====================================+
 * | SW_NO_ERROR | The HKDF is executed successfully. |
 * +-------------+------------------------------------+
 *
 *
 */
smStatus_t Se05x_API_HKDF_Extended(pSe05xSession_t session_ctx,
    uint32_t hmacID,
    SE05x_DigestMode_t digestMode,
    SE05x_HkdfMode_t hkdfMode,
    const uint8_t *salt,
    size_t saltLen,
    uint32_t saltID,
    const uint8_t *info,
    size_t infoLen,
    uint32_t derivedKeyID,
    uint16_t deriveDataLen,
    uint8_t *hkdfOuput,
    size_t *phkdfOuputLen);

/** Se05x_API_PBKDF2
 *
 * Password Based Key Derivation Function 2 (PBKDF2) according [RFC8018].
 *
 * The password is an input to the KDF and must be stored inside the .
 *
 * The output is returned to the host.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+----------------------------------------------+
 * | Field | Value      | Description                                  |
 * +=======+============+==============================================+
 * | CLA   | 0x80       |                                              |
 * +-------+------------+----------------------------------------------+
 * | INS   | INS_CRYPTO | :cpp:type:`SE05x_INS_t`                      |
 * +-------+------------+----------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------+----------------------------------------------+
 * | P2    | P2_PBKDF   | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------+----------------------------------------------+
 * | Lc    | #(Payload) |                                              |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte password identifier (object type must |
 * |       |            | be HMACKey)                                  |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_2] | Salt (0 to 64 bytes)   [Optional]            |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_3] | 2-byte Iteration count: 1 up to 0x7FFF.      |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_4] | 2-byte Requested length: 1 up to 512 bytes.  |
 * +-------+------------+----------------------------------------------+
 * | Le    | 0x00       | Expecting derived key material.              |
 * +-------+------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------------------------------+
 * | Value      | Description                         |
 * +============+=====================================+
 * | TLV[TAG_1] | Derived key material (session key). |
 * +------------+-------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID 4-byte password identifier (object type must be HMACKey) [1:kSE05x_TAG_1]
 * @param[in] salt salt [2:kSE05x_TAG_2]
 * @param[in] saltLen Length of salt
 * @param[in] count count [3:kSE05x_TAG_3]
 * @param[in] requestedLen requestedLen [4:kSE05x_TAG_4]
 * @param[out] derivedSessionKey  [0:kSE05x_TAG_1]
 * @param[in,out] pderivedSessionKeyLen Length for derivedSessionKey
 */
smStatus_t Se05x_API_PBKDF2(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *salt,
    size_t saltLen,
    uint16_t count,
    uint16_t requestedLen,
    uint8_t *derivedSessionKey,
    size_t *pderivedSessionKeyLen);

/** Se05x_API_DFDiversifyKey
 *
 *
 * Create a Diversified Key. Input is _divInput_ 1 up to 31 bytes.
 *
 * Note that users need to create the diversified key object before calling this
 * function.
 *
 * Both the master key and the diversified key need the policy
 * POLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION to be set.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+------------------------------------------+
 * | Field | Value        | Description                              |
 * +=======+==============+==========================================+
 * | CLA   | 0x80         |                                          |
 * +-------+--------------+------------------------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`                  |
 * +-------+--------------+------------------------------------------+
 * | P1    | P1_DEFAULT   | See :cpp:type:`SE05x_P1_t`               |
 * +-------+--------------+------------------------------------------+
 * | P2    | P2_DIVERSIFY | See :cpp:type:`SE05x_P2_t`               |
 * +-------+--------------+------------------------------------------+
 * | Lc    | #(Payload)   |                                          |
 * +-------+--------------+------------------------------------------+
 * |       | TLV[TAG_1]   | 4-byte master key identifier.            |
 * +-------+--------------+------------------------------------------+
 * |       | TLV[TAG_2]   | 4-byte diversified key identifier.       |
 * +-------+--------------+------------------------------------------+
 * |       | TLV[TAG_3]   | Byte array containing divInput (up to 31 |
 * |       |              | bytes).                                  |
 * +-------+--------------+------------------------------------------+
 * | Le    |              |                                          |
 * +-------+--------------+------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-----------------------------+--------------------------------------+
 * | SW                          | Description                          |
 * +=============================+======================================+
 * | SW_NO_ERROR                 | The command is handled successfully. |
 * +-----------------------------+--------------------------------------+
 * | SW_CONDITIONS_NOT_SATISFIED | No master key found.                 |
 * +-----------------------------+--------------------------------------+
 * |                             | Wrong length for divInput.           |
 * +-----------------------------+--------------------------------------+
 * @endrst
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] masterKeyID masterKeyID [1:kSE05x_TAG_1]
 * @param[in] diversifiedKeyID diversifiedKeyID [2:kSE05x_TAG_2]
 * @param[in] divInputData divInputData [3:kSE05x_TAG_3]
 * @param[in] divInputDataLen Length of divInputData
 */
smStatus_t Se05x_API_DFDiversifyKey(pSe05xSession_t session_ctx,
    uint32_t masterKeyID,
    uint32_t diversifiedKeyID,
    const uint8_t *divInputData,
    size_t divInputDataLen);

/** Se05x_API_DFAuthenticateFirstPart1
 *
 * MIFARE DESFire support
 *
 * MIFARE DESFire EV2 Key derivation (S-mode). This is limited to AES128 keys
 * only.
 *
 * The SE05X can be used by a card reader to setup a session where the SE05X
 * stores the master key(s) and the session keys are generated and passed to the
 * host.
 *
 * The SE05X keeps an internal state of MIFARE DESFire authentication data during
 * authentication setup. This state is fully transient, so it is lost on deselect
 * of the applet.
 *
 * The MIFARE DESFire state is owned by 1 user at a time; i.e., the user who
 * calls DFAuthenticateFirstPart1 owns the MIFARE DESFire context until
 * DFAuthenticateFirstPart1 is called again or until DFKillAuthentication is
 * called.
 *
 * The SE05X can also be used to support a ChangeKey command, either supporting
 * ChangeKey or ChangeKeyEV2. To establish a correct use case, policies need to
 * be applied to the keys to indicate keys can be used for ChangeKey or not, etc.
 * (to be detailed)
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------------+----------------------------------------------+
 * | Field | Value               | Description                                  |
 * +=======+=====================+==============================================+
 * | CLA   | 0x80                |                                              |
 * +-------+---------------------+----------------------------------------------+
 * | INS   | INS_CRYPTO          | :cpp:type:`SE05x_INS_t`                      |
 * +-------+---------------------+----------------------------------------------+
 * | P1    | P1_DEFAULT          | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+---------------------+----------------------------------------------+
 * | P2    | P2_AUTH_FIRST_PART1 | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+---------------------+----------------------------------------------+
 * | Lc    | #(Payload)          |                                              |
 * +-------+---------------------+----------------------------------------------+
 * |       | TLV[TAG_1]          | 4-byte key identifier.                       |
 * +-------+---------------------+----------------------------------------------+
 * |       | TLV[TAG_2]          | 16-byte encrypted card challenge: E(Kx,RndB) |
 * +-------+---------------------+----------------------------------------------+
 * | Le    | 0x00                |                                              |
 * +-------+---------------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+---------------------------------------------+
 * | Value      | Description                                 |
 * +============+=============================================+
 * | TLV[TAG_1] | 32-byte output data: E(Kx, RandA || RandB') |
 * +------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] inputData inputData [2:kSE05x_TAG_2]
 * @param[in] inputDataLen Length of inputData
 * @param[out] outputData  [0:kSE05x_TAG_1]
 * @param[in,out] poutputDataLen Length for outputData
 */
smStatus_t Se05x_API_DFAuthenticateFirstPart1(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen);

/** Se05x_API_DFAuthenticateNonFirstPart1
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------------+----------------------------------------------+
 * | Field | Value                  | Description                                  |
 * +=======+========================+==============================================+
 * | CLA   | 0x80                   |                                              |
 * +-------+------------------------+----------------------------------------------+
 * | INS   | INS_CRYPTO             | :cpp:type:`SE05x_INS_t`                      |
 * +-------+------------------------+----------------------------------------------+
 * | P1    | P1_DEFAULT             | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------------------+----------------------------------------------+
 * | P2    | P2_AUTH_NONFIRST_PART1 | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------------------+----------------------------------------------+
 * | Lc    | #(Payload)             |                                              |
 * +-------+------------------------+----------------------------------------------+
 * |       | TLV[TAG_1]             | 4-byte key identifier.                       |
 * +-------+------------------------+----------------------------------------------+
 * |       | TLV[TAG_2]             | 16-byte encrypted card challenge: E(Kx,RndB) |
 * +-------+------------------------+----------------------------------------------+
 * | Le    | 0x00                   |                                              |
 * +-------+------------------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+---------------------------------------------+
 * | Value      | Description                                 |
 * +============+=============================================+
 * | TLV[TAG_1] | 32-byte output data: E(Kx, RandA || RandB') |
 * +------------+---------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] objectID objectID [1:kSE05x_TAG_1]
 * @param[in] inputData inputData [2:kSE05x_TAG_2]
 * @param[in] inputDataLen Length of inputData
 * @param[out] outputData  [0:kSE05x_TAG_1]
 * @param[in,out] poutputDataLen Length for outputData
 */
smStatus_t Se05x_API_DFAuthenticateNonFirstPart1(pSe05xSession_t session_ctx,
    uint32_t objectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen);

/** Se05x_API_DFAuthenticateFirstPart2
 *
 * For First part 2, the key identifier is implicitly set to the identifier used
 * for the First authentication. DFAuthenticateFirstPart1 needs to be called
 * before; otherwise an error is returned.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------------+------------------------------------+
 * | Field | Value               | Description                        |
 * +=======+=====================+====================================+
 * | CLA   | 0x80                |                                    |
 * +-------+---------------------+------------------------------------+
 * | INS   | INS_CRYPTO          | :cpp:type:`SE05x_INS_t`            |
 * +-------+---------------------+------------------------------------+
 * | P1    | P1_DEFAULT          | See :cpp:type:`SE05x_P1_t`         |
 * +-------+---------------------+------------------------------------+
 * | P2    | P2_AUTH_FIRST_PART2 | See :cpp:type:`SE05x_P2_t`         |
 * +-------+---------------------+------------------------------------+
 * | Lc    | #(Payload)          |                                    |
 * +-------+---------------------+------------------------------------+
 * |       | TLV[TAG_1]          | 32 byte input:                     |
 * |       |                     | E(Kx,TI||RndA'||PDcap2||PCDcap2)   |
 * +-------+---------------------+------------------------------------+
 * | Le    | 0x00                |                                    |
 * +-------+---------------------+------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------+
 * | Value      | Description                              |
 * +============+==========================================+
 * | TLV[TAG_1] | 12-byte array returning PDcap2||PCDcap2. |
 * +------------+------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-----------------------------+--------------------------------------+
 * | SW                          | Description                          |
 * +=============================+======================================+
 * | SW_NO_ERROR                 | The command is handled successfully. |
 * +-----------------------------+--------------------------------------+
 * | SW_WRONG_DATA               |                                      |
 * +-----------------------------+--------------------------------------+
 * | SW_CONDITIONS_NOT_SATISFIED |                                      |
 * +-----------------------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] inputData inputData [1:kSE05x_TAG_1]
 * @param[in] inputDataLen Length of inputData
 * @param[out] outputData  [0:kSE05x_TAG_1]
 * @param[in,out] poutputDataLen Length for outputData
 */
smStatus_t Se05x_API_DFAuthenticateFirstPart2(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *poutputDataLen);

/** Se05x_API_DFAuthenticateNonFirstPart2
 *
 * For NonFirst part 2, the key identifier is implicitly set to the identifier
 * used for the NonFirst part 1 authentication. DFAuthenticateNonFirstPart1 needs
 * to be called before; otherwise an error is returned.
 *
 * If authentication fails, SW_WRONG_DATA will be returned.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------------+----------------------------+
 * | Field | Value                  | Description                |
 * +=======+========================+============================+
 * | CLA   | 0x80                   |                            |
 * +-------+------------------------+----------------------------+
 * | INS   | INS_CRYPTO             | :cpp:type:`SE05x_INS_t`    |
 * +-------+------------------------+----------------------------+
 * | P1    | P1_DEFAULT             | See :cpp:type:`SE05x_P1_t` |
 * +-------+------------------------+----------------------------+
 * | P2    | P2_AUTH_NONFIRST_PART2 | See :cpp:type:`SE05x_P2_t` |
 * +-------+------------------------+----------------------------+
 * | Lc    | #(Payload)             |                            |
 * +-------+------------------------+----------------------------+
 * |       | TLV[TAG_1]             | 16-byte E(Kx, RndA')       |
 * +-------+------------------------+----------------------------+
 * | Le    | 0x00                   |                            |
 * +-------+------------------------+----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] inputData inputData [1:kSE05x_TAG_1]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_DFAuthenticateNonFirstPart2(
    pSe05xSession_t session_ctx, const uint8_t *inputData, size_t inputDataLen);

/** Se05x_API_DFDumpSessionKeys
 *
 * Dump the Transaction Identifier and the session keys to the host.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+-------------+-----------------------------------+
 * | Field | Value       | Description                       |
 * +=======+=============+===================================+
 * | CLA   | 0x80        |                                   |
 * +-------+-------------+-----------------------------------+
 * | INS   | INS_CRYPTO  | :cpp:type:`SE05x_INS_t`           |
 * +-------+-------------+-----------------------------------+
 * | P1    | P1_DEFAULT  | See :cpp:type:`SE05x_P1_t`        |
 * +-------+-------------+-----------------------------------+
 * | P2    | P2_DUMP_KEY | See :cpp:type:`SE05x_P2_t`        |
 * +-------+-------------+-----------------------------------+
 * | Lc    | #(Payload)  |                                   |
 * +-------+-------------+-----------------------------------+
 * | Le    | 0x28        | Expecting TLV with 38 bytes data. |
 * +-------+-------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------------------------------+
 * | Value      | Description                          |
 * +============+======================================+
 * | TLV[TAG_1] | 38 bytes: KeyID.SesAuthENCKey ||     |
 * |            | KeyID.SesAuthMACKey || TI || Cmd-Ctr |
 * +------------+--------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[out] sessionData 38 bytes: KeyID.SesAuthENCKey || KeyID.SesAuthMACKey || TI || Cmd-Ctr [0:kSE05x_TAG_1]
 * @param[in,out] psessionDataLen Length for sessionData
 */
smStatus_t Se05x_API_DFDumpSessionKeys(pSe05xSession_t session_ctx, uint8_t *sessionData, size_t *psessionDataLen);

/** Se05x_API_DFChangeKeyPart1
 *
 *
 * The DFChangeKeyPart1 command is supporting the function to change keys on the
 * DESFire PICC. The command generates the cryptogram required to perform such
 * operation.
 *
 * The new key and, if used, the current (or old) key must be stored in the SE05X
 * and have the POLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION associated to execute
 * this command. This means the new PICC key must have been loaded into the SE05X
 * prior to issuing this command.
 *
 * The 1-byte key set number indicates whether DESFire ChangeKey or DESFire
 * ChangeKeyEV2 is used. When key set equals 0xFF, ChangeKey is used.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------------+------------------------------------------------+
 * | Field | Value               | Description                                    |
 * +=======+=====================+================================================+
 * | CLA   | 0x80                |                                                |
 * +-------+---------------------+------------------------------------------------+
 * | INS   | INS_CRYPTO          | :cpp:type:`SE05x_INS_t`                        |
 * +-------+---------------------+------------------------------------------------+
 * | P1    | P1_DEFAULT          | See :cpp:type:`SE05x_P1_t`                     |
 * +-------+---------------------+------------------------------------------------+
 * | P2    | P2_CHANGE_KEY_PART1 | See :cpp:type:`SE05x_P2_t`                     |
 * +-------+---------------------+------------------------------------------------+
 * | Lc    | #(Payload)          |                                                |
 * +-------+---------------------+------------------------------------------------+
 * |       | TLV[TAG_1]          | 4-byte identifier of the old key.   [Optional: |
 * |       |                     | if the authentication key is the same as the   |
 * |       |                     | key to be replaced, this TAG should not be     |
 * |       |                     | present].                                      |
 * +-------+---------------------+------------------------------------------------+
 * |       | TLV[TAG_2]          | 4-byte identifier of the new key.              |
 * +-------+---------------------+------------------------------------------------+
 * |       | TLV[TAG_3]          | 1-byte key set number   [Optional: default =   |
 * |       |                     | 0xC6]                                          |
 * +-------+---------------------+------------------------------------------------+
 * |       | TLV[TAG_4]          | 1-byte DESFire key number to be targeted.      |
 * +-------+---------------------+------------------------------------------------+
 * |       | TLV[TAG_5]          | 1-byte key version                             |
 * +-------+---------------------+------------------------------------------------+
 * | Le    | 0x00                |                                                |
 * +-------+---------------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------+
 * | Value      | Description                 |
 * +============+=============================+
 * | TLV[TAG_1] | Cryptogram holding key data |
 * +------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] oldObjectID oldObjectID [1:kSE05x_TAG_1]
 * @param[in] newObjectID newObjectID [2:kSE05x_TAG_2]
 * @param[in] keySetNr keySetNr [3:kSE05x_TAG_3]
 * @param[in] keyNoDESFire keyNoDESFire [4:kSE05x_TAG_4]
 * @param[in] keyVer keyVer [5:kSE05x_TAG_5]
 * @param[out] KeyData  [0:kSE05x_TAG_1]
 * @param[in,out] pKeyDataLen Length for KeyData
 */
smStatus_t Se05x_API_DFChangeKeyPart1(pSe05xSession_t session_ctx,
    uint32_t oldObjectID,
    uint32_t newObjectID,
    uint8_t keySetNr,
    uint8_t keyNoDESFire,
    uint8_t keyVer,
    uint8_t *KeyData,
    size_t *pKeyDataLen);

/** Se05x_API_DFChangeKeyPart2
 *
 * The DFChangeKeyPart2 command verifies the MAC returned by ChangeKey or
 * ChangeKeyEV2. Note that this function only needs to be called if a MAC is
 * returned (which is not the case if the currently authenticated key is changed
 * on the DESFire card).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------------+----------------------------+
 * | Field | Value               | Description                |
 * +=======+=====================+============================+
 * | CLA   | 0x80                |                            |
 * +-------+---------------------+----------------------------+
 * | INS   | INS_CRYPTO          | :cpp:type:`SE05x_INS_t`    |
 * +-------+---------------------+----------------------------+
 * | P1    | P1_DEFAULT          | See :cpp:type:`SE05x_P1_t` |
 * +-------+---------------------+----------------------------+
 * | P2    | P2_CHANGE_KEY_PART2 | See :cpp:type:`SE05x_P2_t` |
 * +-------+---------------------+----------------------------+
 * | Lc    | #(Payload)          |                            |
 * +-------+---------------------+----------------------------+
 * |       | TLV[TAG_1]          | MAC                        |
 * +-------+---------------------+----------------------------+
 * | Le    | 0x00                |                            |
 * +-------+---------------------+----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-----------------------------------+
 * | Value      | Description                       |
 * +============+===================================+
 * | TLV[TAG_1] | 1-byte :cpp:type:`SE05x_Result_t` |
 * +------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] MAC MAC [1:kSE05x_TAG_1]
 * @param[in] MACLen Length of MAC
 * @param[out] presult  [0:kSE05x_TAG_1]
 */
smStatus_t Se05x_API_DFChangeKeyPart2(pSe05xSession_t session_ctx, const uint8_t *MAC, size_t MACLen, uint8_t *presult);

/** Se05x_API_DFKillAuthentication
 *
 * DFKillAuthentication invalidates any authentication and clears the internal
 * DESFire state. Keys used as input (master keys or diversified keys) are not
 * touched.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+--------------+----------------------------+
 * | Field | Value        | Description                |
 * +=======+==============+============================+
 * | CLA   | 0x80         |                            |
 * +-------+--------------+----------------------------+
 * | INS   | INS_CRYPTO   | :cpp:type:`SE05x_INS_t`    |
 * +-------+--------------+----------------------------+
 * | P1    | P1_DEFAULT   | See :cpp:type:`SE05x_P1_t` |
 * +-------+--------------+----------------------------+
 * | P2    | P2_KILL_AUTH | See :cpp:type:`SE05x_P2_t` |
 * +-------+--------------+----------------------------+
 * | Lc    | #(Payload)   |                            |
 * +-------+--------------+----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 */
smStatus_t Se05x_API_DFKillAuthentication(pSe05xSession_t session_ctx);

/** Se05x_API_TLSGenerateRandom
 *
 * Generates a random that is stored in the SE05X and used by TLSPerformPRF.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-----------------------------------+
 * | Field | Value      | Description                       |
 * +=======+============+===================================+
 * | CLA   | 0x80       |                                   |
 * +-------+------------+-----------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`       |
 * +-------+------------+-----------------------------------+
 * | P1    | P1_TLS     | See :cpp:type:`SE05x_P1_t`        |
 * +-------+------------+-----------------------------------+
 * | P2    | P2_RANDOM  | See :cpp:type:`SE05x_P2_t`        |
 * +-------+------------+-----------------------------------+
 * | Lc    | #(Payload) |                                   |
 * +-------+------------+-----------------------------------+
 * | Le    | 0x22       | Expecting TLV with 32 bytes data. |
 * +-------+------------+-----------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------+
 * | Value      | Description          |
 * +============+======================+
 * | TLV[TAG_1] | 32-byte random value |
 * +------------+----------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[out] randomValue  [0:kSE05x_TAG_1]
 * @param[in,out] prandomValueLen Length for randomValue
 */
smStatus_t Se05x_API_TLSGenerateRandom(pSe05xSession_t session_ctx, uint8_t *randomValue, size_t *prandomValueLen);

/** Se05x_API_TLSCalculatePreMasterSecret
 *
 * The command TLSCalculatePreMasterSecret will compute the pre-master secret for
 * TLS according [RFC5246]. The pre-master secret will always be stored in an
 * HMACKey object (TLV[TAG_3]). The HMACKey object must be created before;
 * otherwise the calculation of the pre-master secret will fail.
 *
 * It can use one of these algorithms: - - - -
 *
 *   * PSK Key Exchange algorithm as defined in [RFC4279]
 *
 *   * RSA_PSK Key Exchange algorithm as defined in [RFC4279]
 *
 *   * ECDHE_PSK Key Exchange algorithm as defined in  [RFC5489]
 *
 *   * EC Key Exchange algorithm as defined in [RFC4492]
 *
 *   * RSA Key Exchange algorithm as defined in [RFC5246]
 *
 *
 * TLV[TAG_1] needs to be an (existing) HMACKey identifier containing the pre-
 * shared Key.
 *
 * Input data in TLV[TAG_4] are:
 *
 *   * An EC public key when TLV[TAG_2] refers to an EC key pair.
 *
 *   * An RSA encrypted secret when TLV[TAG_2] refers to an RSA key pair.
 *
 *   * Empty when TLV[TAG_2] is absent or empty.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+----------------------------------------------+
 * | Field | Value      | Description                                  |
 * +=======+============+==============================================+
 * | CLA   | 0x80       |                                              |
 * +-------+------------+----------------------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`                  |
 * +-------+------------+----------------------------------------------+
 * | P1    | P1_TLS     | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------+----------------------------------------------+
 * | P2    | P2_PMS     | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------+----------------------------------------------+
 * | Lc    | #(Payload) |                                              |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_1] | 4-byte PSK identifier referring to a 16, 32, |
 * |       |            | 48 or 64-byte Pre Shared Key.   [Optional]   |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_2] | 4-byte key pair identifier.   [Optional]     |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_3] | 4-byte target HMACKey identifier.            |
 * +-------+------------+----------------------------------------------+
 * |       | TLV[TAG_4] | Byte array containing input data.            |
 * +-------+------------+----------------------------------------------+
 * | Le    | -          |                                              |
 * +-------+------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] keyPairId keyPairId [1:kSE05x_TAG_1]
 * @param[in] pskId pskId [2:kSE05x_TAG_2]
 * @param[in] hmacKeyId hmacKeyId [3:kSE05x_TAG_3]
 * @param[in] inputData inputData [4:kSE05x_TAG_4]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_TLSCalculatePreMasterSecret(pSe05xSession_t session_ctx,
    uint32_t keyPairId,
    uint32_t pskId,
    uint32_t hmacKeyId,
    const uint8_t *inputData,
    size_t inputDataLen);

/** Se05x_API_TLSPerformPRF
 *
 * The command TLSPerformPRF will compute either:
 *
 *   * the master secret for TLS according [RFC5246], section 8.1
 *
 *   * key expansion data from a master secret for TLS according [RFC5246], section 6.3
 *
 * Each time before calling this function, TLSGenerateRandom must be called.
 * Executing this function will clear the random that is stored in the SE05X .
 *
 * The function can be called as client or as server and either using the pre-
 * master secret or master secret as input, stored in an HMACKey. The input
 * length must be either 16, 32, 48 or 64 bytes.
 *
 * This results in P2 having 4 possibilities:
 *
 *   * P2_TLS_PRF_CLI_HELLO: pass the clientHelloRandom to calculate a master secret, the serverHelloRandom is in SE05X , generated by TLSGenerateRandom.
 *
 *   * P2_TLS_PRF_SRV_HELLO: pass the serverHelloRandom to calculate a master secret, the clientHelloRandom is in SE05X , generated by TLSGenerateRandom.
 *
 *   * P2_TLS_PRF_CLI_RANDOM: pass the clientRandom to generate key expansion data, the serverRandom is in SE05X , generated by TLSGenerateRandom.
 *
 *   * P2_TLS_PRF_SRV_RANDOM: pass the serverRandom to generate key expansion data, the clientRandom is in SE05X
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------------+-----------------------------------------------+
 * | Field | Value                  | Description                                   |
 * +=======+========================+===============================================+
 * | CLA   | 0x80                   |                                               |
 * +-------+------------------------+-----------------------------------------------+
 * | INS   | INS_CRYPTO             | See :cpp:type:`SE05x_INS_t`                   |
 * +-------+------------------------+-----------------------------------------------+
 * | P1    | P1_TLS                 | See :cpp:type:`SE05x_P1_t`                    |
 * +-------+------------------------+-----------------------------------------------+
 * | P2    | See description above. | See :cpp:type:`SE05x_P2_t`                    |
 * +-------+------------------------+-----------------------------------------------+
 * | Lc    | #(Payload)             |                                               |
 * +-------+------------------------+-----------------------------------------------+
 * |       | TLV[TAG_1]             | 4-byte HMACKey identifier.                    |
 * +-------+------------------------+-----------------------------------------------+
 * |       | TLV[TAG_2]             | 1-byte :cpp:type:`SE05x_DigestMode_t`, except |
 * |       |                        | DIGEST_NO_HASH.                               |
 * +-------+------------------------+-----------------------------------------------+
 * |       | TLV[TAG_3]             | Label (1 to 64 bytes)                         |
 * +-------+------------------------+-----------------------------------------------+
 * |       | TLV[TAG_4]             | 32-byte random                                |
 * +-------+------------------------+-----------------------------------------------+
 * |       | TLV[TAG_5]             | 2-byte requested length                       |
 * +-------+------------------------+-----------------------------------------------+
 * | Le    | 0x00                   |                                               |
 * +-------+------------------------+-----------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------------------+
 * | Value      | Description                                  |
 * +============+==============================================+
 * | TLV[TAG_1] | Byte array containing requested output data. |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 *
 * @param[in]  session_ctx     The session context
 * @param[in]  objectID        The object id
 * @param[in]  digestAlgo      The digest algorithm
 * @param[in]  label           The label
 * @param[in]  labelLen        The label length
 * @param[in]  random          The random
 * @param[in]  randomLen       The random length
 * @param[in]  reqLen          The request length
 * @param      outputData      The output data
 * @param      poutputDataLen  The poutput data length
 * @param[in]  tlsprf          The tlsprf
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_TLSPerformPRF(pSe05xSession_t session_ctx,
    uint32_t objectID,
    uint8_t digestAlgo,
    const uint8_t *label,
    size_t labelLen,
    const uint8_t *random,
    size_t randomLen,
    uint16_t reqLen,
    uint8_t *outputData,
    size_t *poutputDataLen,
    const SE05x_TLSPerformPRFType_t tlsprf);

/** Se05x_API_I2CM_ExecuteCommandSet
 *
 * Execute one or multiple I2C commands in master mode. Execution is conditional
 * to the presence of the authentication object identified by
 * RESERVED_ID_I2CM_ACCESS. If the credential is not present in the eSE, access
 * is allowed in general. Otherwise, a session shall be established before
 * executing this command. In this case, the I2CM_ExecuteCommandSet command shall
 * be sent within the mentioned session.
 *
 * The I2C command set is constructed as a sequence of instructions described in
 * with the following rules:
 *
 *   * The length should be limited to MAX_I2CM_COMMAND_LENGTH.
 *
 *   * The data to be read cannot exceed MAX_I2CM_COMMAND_LENGTH, including protocol overhead.
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+------------------------------------------------+
 * | Field | Value      | Description                                    |
 * +=======+============+================================================+
 * | CLA   | 0x80       |                                                |
 * +-------+------------+------------------------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`, in addition to    |
 * |       |            | INS_CRYPTO, users can set the INS_ATTEST flag. |
 * |       |            | In that case, attestation applies.             |
 * +-------+------------+------------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                     |
 * +-------+------------+------------------------------------------------+
 * | P2    | P2_I2CM    | See :cpp:type:`SE05x_P2_t`                     |
 * +-------+------------+------------------------------------------------+
 * | Lc    | #(Payload) |                                                |
 * +-------+------------+------------------------------------------------+
 * |       | TLV[TAG_1] | Byte array containing I2C Command set as TLV   |
 * |       |            | array.                                         |
 * +-------+------------+------------------------------------------------+
 * |       | TLV[TAG_2] | 4-byte attestation object identifier.          |
 * |       |            | [Optional]   [Conditional: only when           |
 * |       |            | INS_ATTEST is set]                             |
 * +-------+------------+------------------------------------------------+
 * |       | TLV[TAG_3] | 1-byte :cpp:type:`SE05x_AttestationAlgo_t`     |
 * |       |            | [Optional]   [Conditional: only when           |
 * |       |            | INS_ATTEST is set]                             |
 * +-------+------------+------------------------------------------------+
 * |       | TLV[TAG_7] | 16-byte freshness random   [Optional]          |
 * |       |            | [Conditional: only when INS_ATTEST is set]     |
 * +-------+------------+------------------------------------------------+
 * | Le    | 0x00       | Expecting TLV with return data.                |
 * +-------+------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------------+
 * | Value      | Description                                    |
 * +============+================================================+
 * | TLV[TAG_1] | Read response, a bytestring containing a       |
 * |            | sequence of:     *          CONFIGURE (0x01),  |
 * |            | followed by 1 byte of return code (0x5A =      |
 * |            | SUCCESS).            *          WRITE (0x03),  |
 * |            | followed by 1 byte of return code            * |
 * |            | READ (0x04), followed by               -       |
 * |            | Length: 2 bytes in big endian encoded without  |
 * |            | TLV length encoding                      -     |
 * |            | Read bytes                      *              |
 * |            | 0xFF followed by the error return code in case |
 * |            | of a structural error of the incoming buffer   |
 * |            | (too long, for example)                        |
 * +------------+------------------------------------------------+
 * | TLV[TAG_3] | TLV containing 12-byte timestamp               |
 * +------------+------------------------------------------------+
 * | TLV[TAG_4] | TLV containing 16-byte freshness (random)      |
 * +------------+------------------------------------------------+
 * | TLV[TAG_5] | TLV containing 18-byte chip unique ID          |
 * +------------+------------------------------------------------+
 * | TLV[TAG_6] | TLV containing signature over the concatenated |
 * |            | values of TLV[TAG_1], TLV[TAG_3], TLV[TAG_4]   |
 * |            | and TLV[TAG_5].                                |
 * +------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 *
 *
 * @param[in]  session_ctx      The session context
 * @param[in]  inputData        The input data
 * @param[in]  inputDataLen     The input data length
 * @param[in]  attestationID    The attestation id
 * @param[in]  attestationAlgo  The attestation algorithm
 * @param      response         The response
 * @param      presponseLen     The presponse length
 * @param      ptimeStamp       The ptime stamp
 * @param      freshness        The freshness
 * @param      pfreshnessLen    The pfreshness length
 * @param      chipId           The chip identifier
 * @param      pchipIdLen       The pchip identifier length
 * @param      signature        The signature
 * @param      psignatureLen    The psignature length
 * @param      randomAttst      The random attst
 * @param[in]  randomAttstLen   The random attst length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_I2CM_ExecuteCommandSet(pSe05xSession_t session_ctx,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint32_t attestationID,
    uint8_t attestationAlgo,
    uint8_t *response,
    size_t *presponseLen,
    SE05x_TimeStamp_t *ptimeStamp,
    uint8_t *freshness,
    size_t *pfreshnessLen,
    uint8_t *chipId,
    size_t *pchipIdLen,
    uint8_t *signature,
    size_t *psignatureLen,
    uint8_t *randomAttst,
    size_t randomAttstLen);

/** Se05x_API_DigestInit
 *
 * Open a digest operation. The state of the digest operation is kept in the
 * Crypto Object until the Crypto Object is finalized or deleted.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+---------------------------------+
 * | Field | Value      | Description                     |
 * +=======+============+=================================+
 * | CLA   | 0x80       |                                 |
 * +-------+------------+---------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`     |
 * +-------+------------+---------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`      |
 * +-------+------------+---------------------------------+
 * | P2    | P2_INIT    | See :cpp:type:`SE05x_P2_t`      |
 * +-------+------------+---------------------------------+
 * | Lc    | #(Payload) |                                 |
 * +-------+------------+---------------------------------+
 * |       | TLV[TAG_2] | 2-byte Crypto Object identifier |
 * +-------+------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_2]
 */
smStatus_t Se05x_API_DigestInit(pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID);

/** Se05x_API_DigestUpdate
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+---------------------------------+
 * | Field | Value      | Description                     |
 * +=======+============+=================================+
 * | CLA   | 0x80       |                                 |
 * +-------+------------+---------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`     |
 * +-------+------------+---------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`      |
 * +-------+------------+---------------------------------+
 * | P2    | P2_UPDATE  | See :cpp:type:`SE05x_P2_t`      |
 * +-------+------------+---------------------------------+
 * | Lc    | #(Payload) |                                 |
 * +-------+------------+---------------------------------+
 * |       | TLV[TAG_2] | 2-byte Crypto Object identifier |
 * +-------+------------+---------------------------------+
 * |       | TLV[TAG_3] | Data to be hashed.              |
 * +-------+------------+---------------------------------+
 * | Le    |            |                                 |
 * +-------+------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------------+
 * | SW          | Description                          |
 * +=============+======================================+
 * | SW_NO_ERROR | The command is handled successfully. |
 * +-------------+--------------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_2]
 * @param[in] inputData inputData [2:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 */
smStatus_t Se05x_API_DigestUpdate(
    pSe05xSession_t session_ctx, SE05x_CryptoObjectID_t cryptoObjectID, const uint8_t *inputData, size_t inputDataLen);

/** Se05x_API_DigestFinal
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+------------------------------------+
 * | Field | Value      | Description                        |
 * +=======+============+====================================+
 * | CLA   | 0x80       |                                    |
 * +-------+------------+------------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`        |
 * +-------+------------+------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`         |
 * +-------+------------+------------------------------------+
 * | P2    | P2_FINAL   | See :cpp:type:`SE05x_P2_t`         |
 * +-------+------------+------------------------------------+
 * | Lc    | #(Payload) |                                    |
 * +-------+------------+------------------------------------+
 * |       | TLV[TAG_2] | 2-byte Crypto Object identifier    |
 * +-------+------------+------------------------------------+
 * |       | TLV[TAG_3] | Data to be encrypted or decrypted. |
 * +-------+------------+------------------------------------+
 * | Le    | 0x00       | Expecting TLV with hash value.     |
 * +-------+------------+------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------+
 * | Value      | Description |
 * +============+=============+
 * | TLV[TAG_1] | CMAC value  |
 * +------------+-------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+-----------------------------------+
 * | SW          | Description                       |
 * +=============+===================================+
 * | SW_NO_ERROR | The hash is created successfully. |
 * +-------------+-----------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] cryptoObjectID cryptoObjectID [1:kSE05x_TAG_2]
 * @param[in] inputData inputData [2:kSE05x_TAG_3]
 * @param[in] inputDataLen Length of inputData
 * @param[out] cmacValue  [0:kSE05x_TAG_1]
 * @param[in,out] pcmacValueLen Length for cmacValue
 */
smStatus_t Se05x_API_DigestFinal(pSe05xSession_t session_ctx,
    SE05x_CryptoObjectID_t cryptoObjectID,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmacValue,
    size_t *pcmacValueLen);

/** Se05x_API_DigestOneShot
 *
 * Performs a hash operation in one shot (without context).
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-------------------------------------------+
 * | Field | Value      | Description                               |
 * +=======+============+===========================================+
 * | CLA   | 0x80       |                                           |
 * +-------+------------+-------------------------------------------+
 * | INS   | INS_CRYPTO | See :cpp:type:`SE05x_INS_t`               |
 * +-------+------------+-------------------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`                |
 * +-------+------------+-------------------------------------------+
 * | P2    | P2_ONESHOT | See :cpp:type:`SE05x_P2_t`                |
 * +-------+------------+-------------------------------------------+
 * | Lc    | #(Payload) |                                           |
 * +-------+------------+-------------------------------------------+
 * |       | TLV[TAG_1] | 1-byte DigestMode (except DIGEST_NO_HASH) |
 * +-------+------------+-------------------------------------------+
 * |       | TLV[TAG_2] | Data to hash.                             |
 * +-------+------------+-------------------------------------------+
 * | Le    | 0x00       | TLV expecting hash value                  |
 * +-------+------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------+
 * | Value      | Description |
 * +============+=============+
 * | TLV[TAG_1] | Hash value. |
 * +------------+-------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+-----------------------------------+
 * | SW          | Description                       |
 * +=============+===================================+
 * | SW_NO_ERROR | The hash is created successfully. |
 * +-------------+-----------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 * @param[in] digestMode digestMode [1:kSE05x_TAG_1]
 * @param[in] inputData inputData [2:kSE05x_TAG_2]
 * @param[in] inputDataLen Length of inputData
 * @param[out] hashValue  [0:kSE05x_TAG_1]
 * @param[in,out] phashValueLen Length for hashValue
 */
smStatus_t Se05x_API_DigestOneShot(pSe05xSession_t session_ctx,
    uint8_t digestMode,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *hashValue,
    size_t *phashValueLen);

/** Se05x_API_GetVersion
 *
 * Gets the applet version information.
 *
 * This will return 7-byte VersionInfo (including major, minor and patch version
 * of the applet, supported applet features and secure box version).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------------------------+----------------------------------------------+
 * | Field | Value                        | Description                                  |
 * +=======+==============================+==============================================+
 * | CLA   | 0x80                         |                                              |
 * +-------+------------------------------+----------------------------------------------+
 * | INS   | INS_MGMT                     | See :cpp:type:`SE05x_INS_t`                  |
 * +-------+------------------------------+----------------------------------------------+
 * | P1    | P1_DEFAULT                   | See :cpp:type:`SE05x_P1_t`                   |
 * +-------+------------------------------+----------------------------------------------+
 * | P2    | P2_VERSION or P2_VERSION_EXT | See :cpp:type:`SE05x_P2_t`                   |
 * +-------+------------------------------+----------------------------------------------+
 * | Lc    | #(Payload)                   |                                              |
 * +-------+------------------------------+----------------------------------------------+
 * | Le    | 0x00                         | Expecting TLV with 7-byte data  (when P2 =   |
 * |       |                              | P2_VERSION) or a TLV with 37 byte data (when |
 * |       |                              | P2=  P2_VERSION_EXT).                        |
 * +-------+------------------------------+----------------------------------------------+
 * @endrst
 *
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+------------------------------------------------+
 * | Value      | Description                                    |
 * +============+================================================+
 * | TLV[TAG_1] | 7-byte :cpp:type:`VersionInfoRef` (if P2 =     |
 * |            | P2_VERSION) or 7-byte  VersionInfo followed by |
 * |            | 30 bytes extendedFeatureBits (if P2 =          |
 * |            | P2_VERSION_EXT)                                |
 * +------------+------------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 * @param[in]  session_ctx       The session context
 * @param      pappletVersion    The papplet version
 * @param      appletVersionLen  The applet version length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_GetVersion(pSe05xSession_t session_ctx, uint8_t *pappletVersion, size_t *appletVersionLen);

/** Se05x_API_GetTimestamp
 *
 * Gets a monotonic counter value (time stamp) from the operating system of the
 * device (both persistent and transient part). See TimestampFunctionality for
 * details on the timestamps.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-------------------------------+
 * | Field | Value      | Description                   |
 * +=======+============+===============================+
 * | CLA   | 0x80       |                               |
 * +-------+------------+-------------------------------+
 * | INS   | INS_MGMT   | See :cpp:type:`SE05x_INS_t`   |
 * +-------+------------+-------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`    |
 * +-------+------------+-------------------------------+
 * | P2    | P2_TIME    | See :cpp:type:`SE05x_P2_t`    |
 * +-------+------------+-------------------------------+
 * | Lc    | #(Payload) |                               |
 * +-------+------------+-------------------------------+
 * | Le    | 0x2C       | Expecting TLV with timestamp. |
 * +-------+------------+-------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+-------------------------------------------+
 * | Value      | Description                               |
 * +============+===========================================+
 * | TLV[TAG_1] | TLV containing a 12-byte operating system |
 * |            | timestamp.                                |
 * +------------+-------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in]  session_ctx  The session context
 * @param      ptimeStamp   The ptime stamp
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_GetTimestamp(pSe05xSession_t session_ctx, SE05x_TimeStamp_t *ptimeStamp);

/** Se05x_API_GetFreeMemory
 *
 * Gets the amount of free memory. MemoryType indicates the type of memory.
 *
 * The result indicates the amount of free memory. Note that behavior of the
 * function might not be fully linear and can have a granularity of 16 bytes
 * where the applet will typically report the "worst case" amount. For example,
 * when allocating 2 bytes a time, the first report will show 16 bytes being
 * allocated, which remains the same for the next 7 allocations of 2 bytes.
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+---------------------------------+
 * | Field | Value      | Description                     |
 * +=======+============+=================================+
 * | CLA   | 0x80       |                                 |
 * +-------+------------+---------------------------------+
 * | INS   | INS_MGMT   | See :cpp:type:`SE05x_INS_t`     |
 * +-------+------------+---------------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`      |
 * +-------+------------+---------------------------------+
 * | P2    | P2_MEMORY  | See :cpp:type:`SE05x_P2_t`      |
 * +-------+------------+---------------------------------+
 * | Lc    | #(Payload) |                                 |
 * +-------+------------+---------------------------------+
 * |       | TLV[TAG_1] | :cpp:type:`SE05x_MemTyp_t`      |
 * +-------+------------+---------------------------------+
 * | Le    | 0x04       | Expecting TLV with 2-byte data. |
 * +-------+------------+---------------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+----------------------------------------------+
 * | Value      | Description                                  |
 * +============+==============================================+
 * | TLV[TAG_1] | 2 bytes indicating the amount of free memory |
 * |            | of the requested memory type.  0x7FFF as     |
 * |            | response means at least 32768 bytes are      |
 * |            | available.                                   |
 * +------------+----------------------------------------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in]  session_ctx  The session context
 * @param[in]  memoryType   The memory type
 * @param      pfreeMem     The pfree memory
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_GetFreeMemory(pSe05xSession_t session_ctx, SE05x_MemoryType_t memoryType, uint16_t *pfreeMem);

/** Se05x_API_GetRandom
 *
 * Gets random data from the SE05X .
 *
 *
 * # Command to Applet
 *
 * @rst
 * +-------+------------+-----------------------------+
 * | Field | Value      | Description                 |
 * +=======+============+=============================+
 * | CLA   | 0x80       |                             |
 * +-------+------------+-----------------------------+
 * | INS   | INS_MGMT   | See :cpp:type:`SE05x_INS_t` |
 * +-------+------------+-----------------------------+
 * | P1    | P1_DEFAULT | See :cpp:type:`SE05x_P1_t`  |
 * +-------+------------+-----------------------------+
 * | P2    | P2_RANDOM  | See :cpp:type:`SE05x_P2_t`  |
 * +-------+------------+-----------------------------+
 * | Lc    | #(Payload) |                             |
 * +-------+------------+-----------------------------+
 * |       | TLV[TAG_1] | 2-byte requested size.      |
 * +-------+------------+-----------------------------+
 * | Le    | 0x00       | Expecting random data       |
 * +-------+------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * @rst
 * +------------+--------------+
 * | Value      | Description  |
 * +============+==============+
 * | TLV[TAG_1] | Random data. |
 * +------------+--------------+
 * @endrst
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in]  session_ctx     The session context
 * @param[in]  size            The size
 * @param      randomData      The random data
 * @param      prandomDataLen  The prandom data length
 *
 * @return     The sm status.
 */
smStatus_t Se05x_API_GetRandom(pSe05xSession_t session_ctx, uint16_t size, uint8_t *randomData, size_t *prandomDataLen);

/** Se05x_API_DeleteAll
 *
 * Delete all Secure Objects, delete all curves and Crypto Objects. Secure
 * Objects that are trust provisioned by NXP are not deleted (i.e., all objects
 * that have Origin set to ORIGIN_PROVISIONED, including the objects with
 * reserved object identifiers listed in Object attributes).
 *
 * This command can only be used from sessions that are authenticated using the
 * credential with index RESERVED_ID_FACTORY_RESET.
 *
 * _Important_ : if a secure messaging session is up & running (e.g., AESKey or
 * ECKey session) and the command is sent within this session, the response of
 * the DeleteAll command will not be wrapped (i.e., not encrypted and no R-MAC),
 * so this will also break down the secure channel protocol (as the session is
 * closed by the DeleteAll command itself).
 *
 * # Command to Applet
 *
 * @rst
 * +-------+---------------+-----------------------------+
 * | Field | Value         | Description                 |
 * +=======+===============+=============================+
 * | CLA   | 0x80          |                             |
 * +-------+---------------+-----------------------------+
 * | INS   | INS_MGMT      | See :cpp:type:`SE05x_INS_t` |
 * +-------+---------------+-----------------------------+
 * | P1    | P1_DEFAULT    | See :cpp:type:`SE05x_P1_t`  |
 * +-------+---------------+-----------------------------+
 * | P2    | P2_DELETE_ALL | See :cpp:type:`SE05x_P2_t`  |
 * +-------+---------------+-----------------------------+
 * | Lc    | 0x00          |                             |
 * +-------+---------------+-----------------------------+
 * @endrst
 *
 * # R-APDU Body
 *
 * NA
 *
 * # R-APDU Trailer
 *
 * @rst
 * +-------------+--------------------------------+
 * | SW          | Description                    |
 * +=============+================================+
 * | SW_NO_ERROR | Data is returned successfully. |
 * +-------------+--------------------------------+
 * @endrst
 *
 *
 *
 * @param[in] session_ctx Session Context [0:kSE05x_pSession]
 */
smStatus_t Se05x_API_DeleteAll(pSe05xSession_t session_ctx);

#if SSS_HAVE_SE05X_VER_GTE_04_04
#include "se05x_04_xx_APDU_apis.h"
#endif

#endif /* SE050X_APDU_APIS_H_INC */
