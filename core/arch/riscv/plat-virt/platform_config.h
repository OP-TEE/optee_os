/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 *
 * Brief   Qemu Virt platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* The stack pointer is always kept 16-byte aligned */
#define STACK_ALIGNMENT		16

/* DRAM */
#ifndef DRAM_BASE
#define DRAM_BASE		0x80000000
#define DRAM_SIZE		0x10000000
#endif

/* CLINT */
#ifndef CLINT_BASE
#define CLINT_BASE		0x02000000
#endif

/* PLIC */
#ifndef PLIC_BASE
#define PLIC_BASE		0x0c000000
#define PLIC_REG_SIZE		0x600000
#define PLIC_NUM_SOURCES	0x5f
#endif

/* UART */
#ifndef UART0_BASE
#define UART0_BASE		0x10000000
#endif
#define UART0_IRQ		0x0a

/* RTC */
#ifndef RTC_BASE
#define RTC_BASE		0x101000
#endif
#define RTC_IRQ			0x0b

/* VIRTIO MMIOs */
#define NUM_VIRTIO_MMIOS	8

#ifndef VIRTIO_MMIO1
#define VIRTIO_MMIO1		0x10001000
#define VIRTIO_MMIO1_IRQ	0x01
#endif

#ifndef VIRTIO_MMIO2
#define VIRTIO_MMIO2		0x10002000
#define VIRTIO_MMIO2_IRQ	0x02
#endif

#ifndef VIRTIO_MMIO3
#define VIRTIO_MMIO3		0x10003000
#define VIRTIO_MMIO3_IRQ	0x03
#endif

#ifndef VIRTIO_MMIO4
#define VIRTIO_MMIO4		0x10004000
#define VIRTIO_MMIO4_IRQ	0x04
#endif

#ifndef VIRTIO_MMIO5
#define VIRTIO_MMIO5		0x10005000
#define VIRTIO_MMIO5_IRQ	0x05
#endif

#ifndef VIRTIO_MMIO6
#define VIRTIO_MMIO6		0x10006000
#define VIRTIO_MMIO6_IRQ	0x06
#endif

#ifndef VIRTIO_MMIO7
#define VIRTIO_MMIO7		0x10007000
#define VIRTIO_MMIO7_IRQ	0x07
#endif

#ifndef VIRTIO_MMIO8
#define VIRTIO_MMIO8		0x10008000
#define VIRTIO_MMIO8_IRQ	0x08
#endif

#ifdef CFG_RISCV_MTIME_RATE
#define RISCV_MTIME_RATE CFG_RISCV_MTIME_RATE
#else
#define RISCV_MTIME_RATE 1000000
#endif

#endif /*PLATFORM_CONFIG_H*/
