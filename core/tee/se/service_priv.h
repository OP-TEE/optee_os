/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */

#ifndef TEE_SE_SERVICE_PRIV_H
#define TEE_SE_SERVICE_PRIV_H

TAILQ_HEAD(se_session_head, tee_se_session);

struct tee_se_service {
	/* list of sessions opened on the service */
	struct se_session_head opened_sessions;
	/* list of sessions closed on the service */
	struct se_session_head closed_sessions;
	/* mutex to pretect the session lists */
	struct mutex mutex;
};

#endif
