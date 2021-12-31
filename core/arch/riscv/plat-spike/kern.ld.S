/* SPDX-License-Identifier: (BSD-2-Clause) */
/*
 * Copyright 2022 NXP
 */

#include "../kernel/kern.ld.S"

SECTIONS
{
	.htif HTIF_BASE:
	{
		tohost = .;
		fromhost = tohost + 8;
	}

}
