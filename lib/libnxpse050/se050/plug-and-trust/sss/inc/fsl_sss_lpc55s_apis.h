/*
 * Copyright 2018,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __FSL_SSS_LPC55S_APIS_H__
#define __FSL_SSS_LPC55S_APIS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(SECURE_WORLD)
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include <fsl_sss_lpc55s_types.h>
#include <fsl_sss_mbedtls_apis.h>

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** @copydoc sss_session_open
 *
 */
sss_status_t sss_lpc55s_impl_session_open(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/** @copydoc sss_session_close
 *
 */
void sss_lpc55s_impl_session_close(sss_session_t *session);

/**
 * @addtogroup sss_lpc55s_impl_mac
 * @{
 */
/** @copydoc sss_mac_context_init
 *
 */
sss_status_t sss_lpc55s_impl_mac_context_init(sss_mac_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @copydoc sss_mac_one_go
 *
 */
sss_status_t sss_lpc55s_impl_mac_one_go(
    sss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @copydoc sss_mac_context_free
 *
 */
void sss_lpc55s_impl_mac_context_free(sss_mac_t *context);

/** Re-define sss_host_session_open to be redirected 
 *  from HashCrypt session open 
 */
#ifdef sss_host_session_open
#undef sss_host_session_open
#       define sss_host_session_open(session,subsystem,application_id,connection_type,connectionData) \
            sss_lpc55s_impl_session_open((session),(subsystem),(application_id),(connection_type),(connectionData))
#endif

/** Re-define sss_host_session_close to be redirected 
 *  from HashCrypt session open 
 */
#ifdef sss_host_session_close
#undef sss_host_session_close
#       define sss_host_session_close(session) \
            sss_lpc55s_impl_session_close((session))
#endif

/** Re-define sss_host_mac_context_init to be redirected 
 *  from HashCrypt MAC operations 
 */
#ifdef sss_host_mac_context_init
#undef sss_host_mac_context_init
#       define sss_host_mac_context_init(context,session,keyObject,algorithm,mode) \
            sss_lpc55s_impl_mac_context_init((context),(session),(keyObject),(algorithm),(mode))
#endif

/** Re-define sss_host_mac_one_go to be redirected 
 *  from HashCrypt MAC operations 
 */
#ifdef sss_host_mac_one_go
#undef sss_host_mac_one_go
#       define sss_host_mac_one_go(context,message,messageLen,mac,macLen) \
            sss_lpc55s_impl_mac_one_go((context),(message),(messageLen),(mac),(macLen))
#endif

/** Re-define sss_host_mac_context_free to be redirected 
 *  from HashCrypt MAC operations 
 */
#ifdef sss_host_mac_context_free
#undef sss_host_mac_context_free
#       define sss_host_mac_context_free(context) \
            sss_lpc55s_impl_mac_context_free((context))
#endif

/* clang-format on */
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */
#endif /* SECURE_WORLD */

#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

#endif /* __FSL_SSS_LPC55S_APIS_H__ */
