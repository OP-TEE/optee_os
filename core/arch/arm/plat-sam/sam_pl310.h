/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Microchip Technology Inc. and its subsidiaries.
 */

#ifndef __SAM_PL310_H__
#define __SAM_PL310_H__

TEE_Result pl310_enable(void);
TEE_Result pl310_disable(void);
TEE_Result pl310_enable_writeback(void);
TEE_Result pl310_disable_writeback(void);

#endif /* __SAM_PL310_H__ */
