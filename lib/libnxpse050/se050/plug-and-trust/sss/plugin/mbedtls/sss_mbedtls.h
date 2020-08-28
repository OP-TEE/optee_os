/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * Implementation of key association between NXP Secure Element and mbedtls.
 * @par History
 * 1.0   30-jan-2018 : Initial version
 *
 *****************************************************************************/

#ifndef AX_MBEDTLS_H
#define AX_MBEDTLS_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ALT_SSS
#include "sss_mbedtls.h"
#else
#include "ax_mbedtls.h"
#endif

#include <fsl_sss_api.h>

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM
#include <fsl_sscp_a71ch.h>
#endif
#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif

/** @ingroup ax_mbed_tls */
/** @{ */

#include "fsl_sss_api.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"

/**
 * @brief      Associate a keypair provisioned in the secure element for
 *             subsequent operations.
 *
 * @param[out] pkey       Pointer to the mbedtls_pk_context which will be
 *                        associated with data corresponding to the key_index
 *
 * @param[in]  pkeyObject The object that we are going to be use.
 *
 * @return     0 if successful, or 1 if unsuccessful
 */
int sss_mbedtls_associate_keypair(mbedtls_pk_context *pkey, sss_object_t *pkeyObject);

/**
 * @brief      Associate a pubkey provisioned in the secure element for
 *             subsequent operations.
 *
 * @param[out] pkey       Pointer to the mbedtls_pk_context which will be
 *                        associated with data corresponding to the key index
 *
 * @param[in]  pkeyObject The object that we are going to be use.
 *
 * @return     0 if successful, or 1 if unsuccessful
 */
int sss_mbedtls_associate_pubkey(mbedtls_pk_context *pkey, sss_object_t *pkeyObject);

/**
 * @brief         Update ECDSA HandShake key with given inded.
 *
 * @param[in,out] handshake  Pointer to the mbedtls_ssl_handshake_params which
 *                           will be associated with data corresponding to the
 *                           key index
 *
 * @param[in]  pkeyObject The object that we are going to be use.
 *
 * @param[in] hostKs Keystore to host for session key.
 *
 * @return        0 if successful, or 1 if unsuccessful
 */

int sss_mbedtls_associate_ecdhctx(
    mbedtls_ssl_handshake_params *handshake, sss_object_t *pkeyObject, sss_key_store_t *hostKs);

/** @} */

/**
 * \brief           This function frees the components of a key pair. Original implementation
 * \param key       The key pair to free.
 */
void mbedtls_ecp_keypair_free_o(mbedtls_ecp_keypair *key);

/**
 * same as  ``mbedtls_ecp_tls_read_group``
 */
int mbedtls_ecp_tls_read_group_o(mbedtls_ecp_group *grp, const unsigned char **buf, size_t len);

#endif /* AX_MBEDTLS_H */
