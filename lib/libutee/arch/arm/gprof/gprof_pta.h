/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __GPROF_PTA_H
#define __GPROF_PTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

TEE_Result __pta_gprof_send(void *buf, size_t len, uint32_t *id);
TEE_Result __pta_gprof_pc_sampling_start(void *buf, size_t len, size_t offset,
					 size_t scale);
TEE_Result __pta_gprof_pc_sampling_stop(uint32_t *rate);
void __pta_gprof_fini(void);
#endif /* __GPROF_PTA_H */
