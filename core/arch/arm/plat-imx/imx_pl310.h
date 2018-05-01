/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 */
#ifndef __IMX_PL310_H__
#define __IMX_PL310_H__

uint32_t pl310_enable(void);
uint32_t pl310_disable(void);
uint32_t pl310_enable_writeback(void);
uint32_t pl310_disable_writeback(void);
uint32_t pl310_enable_wflz(void);

#endif /* __IMX_PL310_H__ */

