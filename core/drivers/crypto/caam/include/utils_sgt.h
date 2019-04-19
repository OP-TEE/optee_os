/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    utils_sgt.h
 *
 * @brief   Scatter-Gather Table management utilities header.
 */
#ifndef __UTILS_SGT_H__
#define __UTILS_SGT_H__

/**
 * @brief   Cache operation on SGT table
 *
 * @param[in] op     Cache operation
 * @param[in] insgt  SGT table
 */
void caam_cache_op_sgt(enum utee_cache_operation op, struct sgtbuf *insgt);

#endif /* __UTILS_SGT_H__ */
