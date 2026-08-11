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

#define PAS_MD_SLOTS		CFG_PAS_MD_SLOTS

struct pas_md_slot {
	void *meta_data;
	size_t meta_data_size;
	uint32_t pas_id;
	bool in_use;
	struct pas_mbn mbn;
	bool ready;
};

struct qcom_pas_session {
	struct pas_md_slot slots[PAS_MD_SLOTS];
};

#endif /* __QCOM_PAS_PRIV_H */
