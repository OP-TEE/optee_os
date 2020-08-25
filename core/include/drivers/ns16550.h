/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2020, Linaro Limited
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
#ifndef NS16550_H
#define NS16550_H

#include <drivers/serial.h>
#include <io.h>
#include <types_ext.h>

#define IO_WIDTH_U8		0
#define IO_WIDTH_U32		1

struct ns16550_data {
	struct io_pa_va base;
	struct serial_chip chip;
	uint8_t io_width;
	uint8_t reg_shift;
};

static inline unsigned int serial_in(vaddr_t addr, uint8_t io_width)
{
	if (io_width == IO_WIDTH_U32)
		return io_read32(addr);
	else
		return io_read8(addr);
}

static inline void serial_out(vaddr_t addr, uint8_t io_width, int ch)
{
	if (io_width == IO_WIDTH_U32)
		io_write32(addr, ch);
	else
		io_write8(addr, ch);
}

void ns16550_init(struct ns16550_data *pd, paddr_t base, uint8_t io_width,
		  uint8_t reg_shift);

#endif /* NS16550_H */
