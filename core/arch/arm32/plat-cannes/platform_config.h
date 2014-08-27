/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
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

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#define CPU_IOMEM_BASE		0x08760000
#define PL310_BASE		(CPU_IOMEM_BASE + 0x2000)
#define GIC_DIST_BASE		(CPU_IOMEM_BASE + 0x1000)
#define SCU_BASE		(CPU_IOMEM_BASE + 0x0000)
#define GIC_CPU_BASE		(CPU_IOMEM_BASE + 0x0100)

#define CPU_PORT_FILT_START	0x40000000
#define CPU_PORT_FILT_END	0xC0000000

#define STXHxxx_LPM_PERIPH_BASE	0x09400000
#define ST_ASC20_REGS_BASE	(STXHxxx_LPM_PERIPH_BASE + 0x00130000)
#define ST_ASC21_REGS_BASE	(STXHxxx_LPM_PERIPH_BASE + 0x00131000)
#define ASC_NUM			20
#define UART_CONSOLE_BASE	ST_ASC20_REGS_BASE

#define RNG_BASE		0x08A89000

#endif /*PLATFORM_CONFIG_H*/
