/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */
#ifndef __IMX7ULP_CRM_H__
#define __IMX7ULP_CRM_H__

#include <util.h>

#define PCC_CGC_BIT_SHIFT	30

#define PCC_ENABLE_CLOCK	BIT32(PCC_CGC_BIT_SHIFT)
#define PCC_DISABLE_CLOCK	BIT32(0)

#define PCC_CAAM		0x90

#endif /* __IMX7ULP_CRM_H__ */
