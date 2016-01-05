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

#define ST_32BIT_REG(address) (address)

/* Asynchronous Serial Controller control registers */
#ifndef ST_ASC_REGS_BASE
#define ST_ASC_REGS_BASE(n)     ST_ASC##n##_REGS_BASE
#endif /* !ST_ASC_REGS_BASE */
#define ST_ASC_BAUDRATE(n)      ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x00)
#define ST_ASC_TXBUFFER(n)      ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x04)
#define ST_ASC_RXBUFFER(n)      ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x08)
#define ST_ASC_CONTROL(n)       ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x0c)
#define ST_ASC_INTENABLE(n)     ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x10)
#define ST_ASC_STATUS(n)        ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x14)
#define ST_ASC_GUARDTIME(n)     ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x18)
#define ST_ASC_TIMEOUT(n)       ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x1c)
#define ST_ASC_TXRESET(n)       ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x20)
#define ST_ASC_RXRESET(n)       ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x24)
#define ST_ASC_RETRIES(n)       ST_32BIT_REG(ST_ASC_REGS_BASE(n) + 0x28)

#define BOARD_ASC_BAUDRATE_REG      ST_ASC_BAUDRATE(ASC_NUM)
#define BOARD_ASC_CONTROL_REG       ST_ASC_CONTROL(ASC_NUM)
#define BOARD_ASC_TXBUFFER_REG      ST_ASC_TXBUFFER(ASC_NUM)
#define BOARD_ASC_STATUS_REG        ST_ASC_STATUS(ASC_NUM)
#define BOARD_ASC_TXRESET_REG       ST_ASC_TXRESET(ASC_NUM)
#define BOARD_ASC_RXRESET_REG       ST_ASC_RXRESET(ASC_NUM)

.section .data
.balign 4

/*
 * ASC IP HW state: 1 not initialized, 0 HW is ready
 * Note that we rely on NonSecure host to setup the HW.
 */
asc_state:
	.word 1


.section .text
.align 5

/*
 * int asc_init(void) - init ASC driver.
 *
 * At least only maps (MMU) the ASC register addresses.
 * We rely on some other SW layer to enable ASC IP (power/clamps/clocks/...)
 */
FUNC asc_init , :
    ldr r1, =asc_state
    mov r0, #0
    str r0, [r1]

    /* TODO: insure ASC is mapped (check against core_init_mmu()/core_mmu.c) */
    ldr r0, =0
    bx lr
END_FUNC asc_init

/*
 * int __asc_xmit(char*) - Transmit a numm terminated string.
 *
 *    R0 is pointer to null-terminated string
 *    Clobbers r0-r3
 */
FUNC __asc_xmit , :

    ldr r1, =asc_state
    ldr r1, [r1]
    cmp r1, #0
    bne _asc_exit

    LDR r2, =BOARD_ASC_TXBUFFER_REG
    LDR r3, =BOARD_ASC_STATUS_REG

    /* Output byte */
nextchr:
    /* Spin until TX FIFO ready */
crwait:
    LDR r1, [r3]
    ANDS r1, r1, #0x04    /* AND TX FIFO HALF EMPTY flag */
    BEQ crwait            /* ANDS should have set Z bit if zero */

    LDRB r1, [r0], #1
    ANDS r1, r1, r1
    BEQ  _asc_exit
    CMP r1, #0xa          /* r1 == \n (line feed) ? */
    BNE notlf

    /* Transmit character extra carriage return for each line feed */
    LDR r1, =0x0d
    STR r1, [r2]

    LDR r1, =0x0a         /* replace line feed */

notlf:
    /* Transmit character */
    STR r1, [r2]

    /* Keep going */
    B nextchr
_asc_exit:
    LDR r0, =0
    BX lr
END_FUNC __asc_xmit

/*
 * void __asc_flush(void) - flush ASC tx fifo.
 *
 *    Clobbers r0-r3
 */
FUNC __asc_flush , :

    ldr r1, =asc_state
    ldr r1, [r1]
    cmp r1, #0
    bne _flush_exit

    LDR r3, =BOARD_ASC_STATUS_REG

flush_wait:
    LDR r1, [r3]
    ANDS r1, r1, #0x02   /* AND TX FIFO EMPTY flag */
    BEQ flush_wait          /* ANDS should have set Z bit if zero */

_flush_exit:
    LDR r0, =0
    BX lr
END_FUNC __asc_flush

/*
 * int __asc_xmit_char(char) - Transmit a single character.
 *
 *    R0 is the 1-byte character to be transmited
 *    Clobbers r0-r3
 */
FUNC __asc_xmit_char , :

    ldr r1, =asc_state
    ldr r1, [r1]
    cmp r1, #0
    bne __asc_char_exit

    LDR r2, =BOARD_ASC_TXBUFFER_REG
    LDR r3, =BOARD_ASC_STATUS_REG

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
END_FUNC __asc_xmit_char
