/*
 * Copyright (c) 2020, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <asm_macros.S>
#include <drivers/console.h>
#include <drivers/ti/uart/uart_16550.h>

	/*
	 * "core" functions are low-level implementations that don't require
	 * writable memory and are thus safe to call in BL1 crash context.
	 */
	.globl console_init
	.globl console_putc
	.globl console_getc
	.globl console_flush

	/*
	 *  The console base is in the data section and not in .bss
	 *  even though it is zero-init. In particular, this allows
	 *  the console functions to start using this variable before
	 *  the runtime memory is initialized for images which do not
	 *  need to copy the .data section from ROM to RAM.
	 */
	.section .data.console_base
	.align 3
console_base:
	.quad 0x0

	/* -----------------------------------------------
	 * int console_init(uintptr_t base_addr,
	 * unsigned int uart_clk, unsigned int baud_rate)
	 * Function to initialize the console without a
	 * C Runtime to print debug information. This
	 * function will be accessed by console_init and
	 * crash reporting.
	 * In: x0 - console base address
	 *     w1 - Uart clock in Hz
	 *     w2 - Baud rate
	 * Out: return 1 on success, 0 on error
	 * Clobber list : x1, x2, x3
	 * -----------------------------------------------
	 */
func console_init
	/* Check the input base address */
	cbz	x0, init_fail
	/* Check baud rate and uart clock for sanity */
	/*  cbz	w1, init_fail
	cbz	w2, init_fail    */

	adr	x3, console_base
	str	x0, [x3]

	/* A clock rate of zero means to skip the initialisation. */
	cbz	w1, skip_init_16550
	
	
	/* Program the baudrate */
	/* Divisor =  Uart clock / (16 * baudrate) */
	lsl	w2, w2, #4
	udiv	w2, w1, w2
	and	w1, w2, #0xff		/* w1 = DLL */
	lsr	w2, w2, #8
	and	w2, w2, #0xff		/* w2 = DLLM */
	ldr	w3, [x0, #UARTLCR]
	orr	w3, w3, #UARTLCR_DLAB
	str	w3, [x0, #UARTLCR]	/* enable DLL, DLLM programming */
	str	w1, [x0, #UARTDLL]	/* program DLL */
	str	w2, [x0, #UARTDLLM]	/* program DLLM */
	mov	w2, #~UARTLCR_DLAB
	and	w3, w3, w2
	str	w3, [x0, #UARTLCR]	/* disable DLL, DLLM programming */

	/* 8n1 */
	mov	w3, #3
	str	w3, [x0, #UARTLCR]
	/* no interrupt */
	mov	w3, #0
	str	w3, [x0, #UARTIER]
#ifdef TI_16550_MDR_QUIRK
	/* UART must be enabled on some platforms via the MDR register */
	str	w3, [x0, #UARTMDR1]
#endif /* TI_16550_MDR_QUIRK */
	/* enable fifo, DMA */
	mov	w3, #(UARTFCR_FIFOEN | UARTFCR_DMAEN)
	str	w3, [x0, #UARTFCR]
	/* DTR + RTS */
	mov	w3, #3
	str	w3, [x0, #UARTMCR]
	mov	w0, #1
	ret
skip_init_16550:
	mov	w0, #1
	ret
init_fail:
	mov	w0, #0
	ret
endfunc console_init

	/* --------------------------------------------------------
	 * int console_putc(int c)
	 * Function to output a character over the console. It
	 * returns the character printed on success or -1 on error.
	 * In : w0 - character to be printed
	 * Out : return -1 on error else return character.
	 * Clobber list : x1, x2
	 * --------------------------------------------------------
	 */
func console_putc
	adr	x1, console_base
	ldr	x1, [x1]

	/* Prepend '\r' to '\n' */
	cmp	w0, #0xA
	b.ne	2f
	/* Check if the transmit FIFO is full */
1:	ldr	w2, [x1, #UARTLSR]
	and	w2, w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	cmp	w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	b.ne	1b
	mov	w2, #0xD		/* '\r' */
	str	w2, [x1, #UARTTX]

	/* Check if the transmit FIFO is full */
2:	ldr	w2, [x1, #UARTLSR]
	and	w2, w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	cmp	w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	b.ne	2b
	str	w0, [x1, #UARTTX]
	ret
endfunc console_putc

	/* ---------------------------------------------
	 * int console_getc(void)
	 * Function to get a character from the console.
	 * It returns the character grabbed on success
	 * or -1 on if no character is available.
	 * Out : w0 - character if available, else -1
	 * Clobber list : x0, x1
	 * ---------------------------------------------
	 */
func console_getc
	adr	x0, console_base
	ldr	x0, [x0]

	/* Check if the receive FIFO is empty */
1:	ldr	w1, [x0, #UARTLSR]
	tbz	w1, #UARTLSR_RDR_BIT, no_char
	ldr	w0, [x0, #UARTRX]
	ret
no_char:
	mov	w0, #ERROR_NO_PENDING_CHAR
	ret
endfunc console_getc

	/* ---------------------------------------------
	 * int console_16550_core_flush(uintptr_t base_addr)
	 * Function to force a write of all buffered
	 * data that hasn't been output.
	 * Out : return -1 on error else return 0.
	 * Clobber list : x0, x1
	 * ---------------------------------------------
	 */
func console_flush
	adr	x0, console_base
	ldr	x0, [x0]

	/* Loop until the transmit FIFO is empty */
1:	ldr	w1, [x0, #UARTLSR]
	and	w1, w1, #(UARTLSR_TEMT | UARTLSR_THRE)
	cmp	w1, #(UARTLSR_TEMT | UARTLSR_THRE)
	b.ne	1b

	mov	w0, #0
	ret
endfunc console_flush
