/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016, Altera Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef AGILEX5_CFG_H
#define AGILEX5_CFG_H

#include <mm/generic_ram_layout.h>

/* UART settings */
#define CONSOLE_UART_BASE  0x10C02000
#define CONSOLE_BAUDRATE       115200
#define CONSOLE_UART_CLK_IN_HZ 100000000

/* Generic Interrupt Controller */
#define GIC_BASE_ADDR 0x1D000000
#define GIC_DIST_OFFSET 0x0
#define GIC_CPU_OFFSET  0x100000

/* DDR memory for dynamic shared memory */
#define DRAM0_BASE 0x80000000
#define DRAM0_SIZE 0x70000000  /* 1792 MB */

#endif /* AGILEX5_CFG_H */
