/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QCOM_PAS_PRIV_H
#define __QCOM_PAS_PRIV_H

#include <pas_mbn_parser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Per-session context shared between the command dispatch (qcom_pas.c) and
 * the authentication backend (pas_auth.c).
 *
 * The firmware metadata is saved at INIT_IMAGE inside a TEE-private copy so
 * the REE cannot alter it between INIT_IMAGE and AUTH_AND_RESET. Keeping it
 * per-session (rather than as a TA global) ensures two concurrent sessions
 * cannot observe each other's metadata.
 *
 * The remoteproc driver opens one TEE session shared by every peripheral,
 * and DSPs load concurrently. Metadata must therefore be keyed by pas_id to
 * prevent one DSP's INIT_IMAGE overwriting another's slot before its
 * AUTH_AND_RESET runs. Hoya platforms expose at most 7 PAS subsystems; size
 * the table with headroom.
 */
#define PAS_MD_SLOTS	8U

struct pas_md_slot {
	void *md;
	size_t md_size;
	uint32_t pas_id;
	bool used;
	struct pas_mbn mbn;
	bool authenticated;
};

struct qcom_pas_session {
	struct pas_md_slot md[PAS_MD_SLOTS];
};

#endif /* __QCOM_PAS_PRIV_H */
