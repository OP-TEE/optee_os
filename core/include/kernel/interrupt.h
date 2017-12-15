/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
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
	void (*raise_pi)(struct itr_chip *chip, size_t it);
	void (*raise_sgi)(struct itr_chip *chip, size_t it,
		uint8_t cpu_mask);
	void (*set_affinity)(struct itr_chip *chip, size_t it,
		uint8_t cpu_mask);
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
void itr_enable(size_t it);
void itr_disable(size_t it);
/* raise the Peripheral Interrupt corresponding to the interrupt ID */
void itr_raise_pi(size_t it);
/*
 * raise the Software Generated Interrupt corresponding to the interrupt ID,
 * the cpu_mask represents which cpu interface to forward.
 */
void itr_raise_sgi(size_t it, uint8_t cpu_mask);
/*
 * let corresponding interrupt forward to the cpu interface
 * according to the cpu_mask.
 */
void itr_set_affinity(size_t it, uint8_t cpu_mask);

#endif /*__KERNEL_INTERRUPT_H*/
