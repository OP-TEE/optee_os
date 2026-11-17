/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef XPU_TARGET_H
#define XPU_TARGET_H

#include <drivers/qcom/xpuv4.h>

/* TZDRAM is secure-APPS only, for both read and write */
#define TZDRAM_XPU_READ_QAD		QAD_APPS_SEC
#define TZDRAM_XPU_WRITE_QAD		QAD_APPS_SEC

/* Only secure APPS may write the DIAG log */
#define DIAG_XPU_WRITE_QAD		QAD_APPS_SEC

/*
 * AP (secure + non-secure), TME ROM, debug, AP boot loader, modem, and
 * PRIME may read the DIAG log.
 */
#define DIAG_XPU_READ_QAD \
	(QAD_ENV_APPS | QAD_TME_ROM | QAD_DEBUG | QAD_AP_QC_BL | QAD_MSA | \
	 QAD_PRIME)

#endif /* XPU_TARGET_H */
