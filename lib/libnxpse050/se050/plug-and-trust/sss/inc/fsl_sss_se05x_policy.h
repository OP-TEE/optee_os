/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FSL_SSS_SE05X_POLICY_H
#define FSL_SSS_SE05X_POLICY_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_policy.h>
#include <fsl_sss_se05x_types.h>
#include <Applet_SE050_Ver.h>

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/** @brief
 *  The function serializes input passed by user (array of sss_policy_t) in to
 *  uin8[] policy buffer
 *
 * @param[in] Array of policies passed by user.
 * @param[out] buffer passed by user where serialized policy data is copied.
 * @param[out] buf_len passed by user where serialized policy data length is copied.
 *
 * @warning Please ensure pbuff is atleast of size MAX_POLICY_BUFFER_SIZE
 *
 */
sss_status_t sss_se05x_create_object_policy_buffer(sss_policy_t *policies, uint8_t *pbuff, size_t *buf_len);
/*! @brief
 *  The function serializes input passed by user (sss_policy_session_u) in to
 *  uin8[] policy buffer
 *
 * @param[in] pointer to sss_policy_session_u passed by user.
 * @param[out] buffer passed by user where serialized policy data is copied.
 * @param[out] buf_len passed by user where serialized policy data length is copied.
 *
 * @warning Please ensure session_pol_buff is atleast of size MAX_POLICY_BUFFER_SIZE
 *
 */
sss_status_t sss_se05x_create_session_policy_buffer(
    sss_policy_session_u *session_policy, uint8_t *session_pol_buff, size_t *buf_len);
#endif /* SSS_HAVE_APPLET_SE05X_IOT */
#endif /* FSL_SSS_SE05X_POLICY_H */
