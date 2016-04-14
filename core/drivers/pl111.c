/*
 * Copyright (c) 2016, Linaro Limited
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

#include <compiler.h>
#include <drivers/pl111.h>
#include <io.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

#define CLCD_TIM0		0x000
#define CLCD_TIM1		0x004
#define CLCD_TIM2		0x008
#define CLCD_TIM3		0x00c
#define CLCD_UBASE		0x010
#define CLCD_LBASE		0x014
#define CLCD_CNTL		0x018
#define CLCD_IMSC		0x01c
#define CLCD_CRSRIMAGE0		0x800
#define CLCD_CRSRCTRL		0xc00
#define CLCD_CRSRCFG		0xc04
#define CLCD_CRSRPLT0		0xc08
#define CLCD_CRSRXY		0xc10

#define CLCD_TIM0_HBP_SHIFT	24
#define CLCD_TIM0_HBP_MASK	0x7f
#define CLCD_TIM0_HFP_SHIFT	16
#define CLCD_TIM0_HFP_MASK	0x7f
#define CLCD_TIM0_HSW_SHIFT	8
#define CLCD_TIM0_HSW_MASK	0x7f
#define CLCD_TIM0_PPL_SHIFT	2
#define CLCD_TIM0_PPL_MASK	0x1f

#define CLCD_TIM1_VBP_SHIFT	24
#define CLCD_TIM1_VBP_MASK	0x7f
#define CLCD_TIM1_VFP_SHIFT	16
#define CLCD_TIM1_VFP_MASK	0x7f
#define CLCD_TIM1_VSW_SHIFT	10
#define CLCD_TIM1_VSW_MASK	0x1f
#define CLCD_TIM1_LPP_SHIFT	0
#define CLCD_TIM1_LPP_MASK	0x1ff

#define CLCD_TIM2_CPL_SHIFT	16
#define CLCD_TIM2_CPL_MASK	0x1ff
#define CLCD_TIM2_BCD		(1 << 26)

#define CLCD_CNTL_EN		(1 << 0)
#define CLCD_CNTL_BPP_SHIFT	1
#define CLCD_CNTL_BPP_MASK	0x7
#define CLCD_CNTL_BPP_24BPP	5
#define CLCD_CNTL_TFT		(1 << 5)
#define CLCD_CNTL_PWR		(1 << 11)

#define CLCD_CRSRXY_X_SHIFT	0
#define CLCD_CRSRXY_X_MASK	0x1ff
#define CLCD_CRSRXY_Y_SHIFT	16
#define CLCD_CRSRXY_Y_MASK	0x1ff


void pl111_init(vaddr_t base, paddr_t frame_base,
		const struct pl111_videomode *m)
{
	uint32_t v;

	v = SHIFT_U32((m->hactive / 16) - 1, CLCD_TIM0_PPL_SHIFT) |
	    SHIFT_U32(m->hback_porch - 1, CLCD_TIM0_HBP_SHIFT) |
	    SHIFT_U32(m->hfront_porch - 1, CLCD_TIM0_HFP_SHIFT) |
	    SHIFT_U32(m->hsync_len - 1, CLCD_TIM0_HSW_SHIFT);
	write32(v, base + CLCD_TIM0);

	v = SHIFT_U32(m->vactive - 1, CLCD_TIM1_LPP_SHIFT) |
	    SHIFT_U32(m->vsync_len, CLCD_TIM1_VSW_SHIFT) |
	    SHIFT_U32(m->vfront_porch, CLCD_TIM1_VFP_SHIFT) |
	    SHIFT_U32(m->vback_porch, CLCD_TIM1_VBP_SHIFT);
	write32(v, base + CLCD_TIM1);

	v = SHIFT_U32(m->hactive - 1, CLCD_TIM2_CPL_SHIFT) | CLCD_TIM2_BCD;
	write32(v, base + CLCD_TIM2);

	write32(0, base + CLCD_TIM3);
	write32(frame_base, base + CLCD_UBASE);
	write32(0, base + CLCD_LBASE);
	write32(0, base + CLCD_IMSC);

	write32(0, base + CLCD_CRSRCFG);

	v = CLCD_CNTL_EN | SHIFT_U32(CLCD_CNTL_BPP_24BPP, CLCD_CNTL_BPP_SHIFT) |
	    CLCD_CNTL_TFT | CLCD_CNTL_PWR;
	write32(v, base + CLCD_CNTL);
}

void pl111_cursor(vaddr_t base, bool on)
{
	write32(on ? 1 : 0, base + CLCD_CRSRCTRL);
}

void pl111_set_cursor_xy(vaddr_t base, size_t x, size_t y)
{
	write32(SHIFT_U32(x, CLCD_CRSRXY_X_SHIFT) |
		SHIFT_U32(y, CLCD_CRSRXY_Y_SHIFT),
		base + CLCD_CRSRXY);
}
