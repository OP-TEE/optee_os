/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
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
