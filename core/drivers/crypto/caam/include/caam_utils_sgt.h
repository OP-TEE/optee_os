/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Scatter-Gather Table management utilities header.
 */
#ifndef __CAAM_UTILS_SGT_H__
#define __CAAM_UTILS_SGT_H__

#include <utee_types.h>

/*
 * Cache operation on SGT table
 *
 * @op     Cache operation
 * @insgt  SGT table
 */
void caam_cache_op_sgt(enum utee_cache_operation op, struct caamsgtbuf *insgt);

#endif /* __CAAM_UTILS_SGT_H__ */
