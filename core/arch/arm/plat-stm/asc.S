/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <platform_config.h>
#include <asm.S>
#include <kernel/unwind.h>

#define ASC_BAUDRATE	0x00
#define ASC_TXBUFFER	0x04
#define ASC_RXBUFFER	0x08
#define ASC_CONTROL	0x0c
#define ASC_INTENABLE	0x10
#define ASC_STATUS	0x14
#define ASC_GUARDTIME	0x18
#define ASC_TIMEOUT	0x1c
#define ASC_TXRESET	0x20
#define ASC_RXRESET	0x24
#define ASC_RETRIES	0x28

.section .text.asc


/*
 * void __asc_flush(vaddr_t base)
 *
 *    Clobbers r0-r3
 */
FUNC __asc_flush , :
UNWIND(	.fnstart)

    ADD r3, r0, #ASC_STATUS

flush_wait:
    LDR r1, [r3]
    ANDS r1, r1, #0x02   /* AND TX FIFO EMPTY flag */
    BEQ flush_wait          /* ANDS should have set Z bit if zero */

    LDR r0, =0
    BX lr
UNWIND(	.fnend)
END_FUNC __asc_flush

/*
 * int __asc_xmit_char(char p, vaddr_t base) - Transmit a single character.
 *
 *    R0 is the 1-byte character to be transmited
 *    R1 is the base address of the uart
 *    Clobbers r0-r3
 */
FUNC __asc_xmit_char , :
UNWIND(	.fnstart)

    ADD r2, r1, #ASC_TXBUFFER
    ADD r3, r1, #ASC_STATUS

    /* Output byte */

    /* Spin until TX FIFO ready */
__asc_char_crwait:
    LDR r1, [r3]
    ANDS r1, r1, #0x04         /* AND TX FIFO HALF EMPTY flag */
    BEQ __asc_char_crwait      /* ANDS should have set Z bit if zero */

    MOVS r1, r0
    LDR r0, =0xFF
    AND r1, r1, r0
    BEQ __asc_char_exit
    CMP r1, #0xa               /* r1 == \n (line feed) ? */
    BNE __asc_char_notlf

    /* Transmit character extra carriage return for each line feed */
    LDR r1, =0x0d
    STR r1, [r2]

    LDR r1, =0x0a              /* replace line feed */

__asc_char_notlf:
    /* Transmit character */
    STR r1, [r2]

__asc_char_exit:
    LDR r0, =0
    BX lr
UNWIND(	.fnend)
END_FUNC __asc_xmit_char
