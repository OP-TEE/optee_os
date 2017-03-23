/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
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

#define GIC_BASE			0xA00000
#define GIC_SIZE			0x8000
#define GICC_OFFSET			0x2000
#define GICD_OFFSET			0x1000
#define UART0_BASE			0x2020000
#define UART1_BASE			0x21E8000
#define UART2_BASE			0x21EC000

#define AHB1_BASE			0x02000000
#define AHB1_SIZE			0x100000
#define AHB2_BASE			0x02100000
#define AHB2_SIZE			0x100000
#define AHB3_BASE			0x02200000
#define AHB3_SIZE			0x100000

#define AIPS_TZ1_BASE_ADDR		0x02000000
#define AIPS1_OFF_BASE_ADDR		(AIPS_TZ1_BASE_ADDR + 0x80000)

#define DRAM0_BASE			0x80000000
#define DRAM0_SIZE			0x20000000

/* Central Security Unit register values */
#define CSU_BASE			0x021C0000
#define CSU_CSL_START			0x0
#define CSU_CSL_END			0xA0
#define CSU_ACCESS_ALL			0x00FF00FF
#define CSU_SETTING_LOCK		0x01000100

