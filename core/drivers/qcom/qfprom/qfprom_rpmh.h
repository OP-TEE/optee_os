/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_RPMH_H__
#define __QFPROM_RPMH_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#define QFPROM_VREG_MODE_RET	U(3)
#define QFPROM_VREG_MODE_LPM	U(5)
#define QFPROM_VREG_MODE_NPM	U(7)

TEE_Result qfprom_rpmh_vote_supply(const char *name, uint32_t voltage_mv,
				   uint32_t off_mode, bool enable);
TEE_Result qfprom_rpmh_vote_mx(uint32_t level);

#endif /* __QFPROM_RPMH_H__ */
