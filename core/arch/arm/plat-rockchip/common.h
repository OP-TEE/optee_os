/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
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

#ifndef PLAT_ROCKCHIP_COMMON_H
#define PLAT_ROCKCHIP_COMMON_H

/* For SMP cpu bootup, they are common for rockchip platforms */
#define LOCK_TAG		0xDEADBEAF
#define LOCK_ADDR_OFFSET	4
#define BOOT_ADDR_OFFSET	8

/*
 * Some register has write-mask bits, it means if you want to set the bits,
 * you need set the write-mask bits at the same time, the write-mask bits is
 * in high 16-bits. The following macro definition helps you access register
 * efficiently.
 */
#define REG_MSK_SHIFT		16
#define WMSK_BIT(nr)		BIT((nr) + REG_MSK_SHIFT)
#define BIT_WITH_WMSK(nr)	(BIT(nr) | WMSK_BIT(nr))
#define BITS_WMSK(msk, shift)	SHIFT_U32(msk, (shift) + REG_MSK_SHIFT)
#define BITS_WITH_WMASK(bits, msk, shift) \
				(SHIFT_U32(bits, shift) | BITS_WMSK(msk, shift))

#endif
