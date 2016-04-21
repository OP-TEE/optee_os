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
#ifndef __KERNEL_INTERRUPT_H
#define __KERNEL_INTERRUPT_H

#include <types_ext.h>
#include <sys/queue.h>

#define ITRF_TRIGGER_LEVEL	(1 << 0)

struct itr_chip {
	const struct itr_ops *ops;
};

struct itr_ops {
	void (*add)(struct itr_chip *chip, size_t it, uint32_t flags);
	void (*enable)(struct itr_chip *chip, size_t it);
	void (*disable)(struct itr_chip *chip, size_t it);
};

enum itr_return {
	ITRR_NONE,
	ITRR_HANDLED,
};

struct itr_handler {
	size_t it;
	uint32_t flags;
	enum itr_return (*handler)(struct itr_handler *h);
	void *data;
	SLIST_ENTRY(itr_handler) link;
};

void itr_init(struct itr_chip *data);
void itr_handle(size_t it);

void itr_add(struct itr_handler *handler);
void itr_enable(struct itr_handler *handler);
void itr_disable(struct itr_handler *handler);

#endif /*__KERNEL_INTERRUPT_H*/
