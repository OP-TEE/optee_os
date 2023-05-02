/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2018 The Hafnium Authors.
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __HAFNIUM_H
#define __HAFNIUM_H

/*
 * This is based on inc/vmapi/hf/abi.h and inc/vmapi/hf/types.h from the
 * Hafnium source tree.
 */

/*
 * Enables a given interrupt ID, returns 0 on success or -1 if the
 * interrupt ID is invalid.
 */
#define HF_INTERRUPT_ENABLE	0xff03

/*
 * Returns the ID of the next pending interrupt, and acknowledges it (i.e.
 * marks it as no longer pending). Returns HF_INVALID_INTID if there are no
 * pending interrupts.
 */
#define HF_INTERRUPT_GET	0xff04

/*
 * Drops the current interrupt priority and deactivate the given interrupt
 * ID.
 */
#define HF_INTERRUPT_DEACTIVATE	0xff08

/* Interrupt ID returned when there is no interrupt pending. */
#define HF_INVALID_INTID	0xffffffff

/* The virtual interrupt ID used for managed exit. */
#define HF_MANAGED_EXIT_INTID	4

#define HF_INTERRUPT_TYPE_IRQ	0
#define HF_INTERRUPT_TYPE_FIQ	1
#define HF_ENABLE		1
#define HF_DISABLE		0

#endif /*__HAFNIUM_H*/
