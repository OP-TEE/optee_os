
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_DATA_H_
#define _PAS_DATA_H_

#include <drivers/clk_qcom.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>


#define PAS_ID_QDSP6		1
#define PAS_ID_WPSS		6
#define PAS_ID_IRIS		9
#define PAS_ID_TURING		18
#define PAS_ID_TURING1		30
#define PAS_ID_CAMERA		33
#define PAS_ID_GPDSP0		39
#define PAS_ID_GPDSP1		40
#define PAS_ID_TURING2		57
#define PAS_ID_TURING3		58
#define PAS_ID_QDSP6_DTB	36
#define PAS_ID_CDSP_DTB		37
#define PAS_ID_HPASS1_DTB	55
#define PAS_ID_HPASS2_DTB	56
#define PAS_ID_CDSP1_DTB	59
#define PAS_ID_CDSP2_DTB	60
#define PAS_ID_CDSP3_DTB	61
#define PAS_ID_HPASS0		PAS_ID_QDSP6
#define PAS_ID_HPASS1		53
#define PAS_ID_HPASS2		54
#define PAS_ID_SOCCP		51
#define PAS_ID_CAMERA1		50

struct qcom_pas_data {
	uint32_t pas_id;
	/* 0-terminated list of PAS_IDs this must load after, or NULL. */
	const uint32_t *depends_on;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	/* Set once fw_start() succeeds; cleared once fw_shutdown() succeeds. */
	bool loaded;
	enum qcom_clk_group clk_group;
	/* Memtype for the controller window: NSEC, or SEC if XPU-gated. */
	enum teecore_memtypes map_type;
};

#endif /* _PAS_DATA_H_ */
