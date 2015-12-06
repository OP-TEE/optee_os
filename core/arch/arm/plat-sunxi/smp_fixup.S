/*
 * Copyright (c) 2014, Allwinner Technology Co., Ltd.
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
#include <asm.S>
#include <kernel/unwind.h>

#define SLAVE_SNOOPCTL_OFFSET	0
#define SNOOPCTL_SNOOP_ENABLE	(1 << 0)
#define SNOOPCTL_DVM_ENABLE	(1 << 1)

#define CCI_STATUS_OFFSET	0xc
#define STATUS_CHANGE_PENDING	(1 << 0)

#define CCI_SLAVE_OFFSET(n)	(0x1000 + 0x1000 * (n))

#define SUNXI_CCI_PHYS_BASE	0x01c90000
#define SUNXI_CCI_SLAVE_A7	3
#define SUNXI_CCI_SLAVE_A15	4
#define SUNXI_CCI_A15_OFFSET	CCI_SLAVE_OFFSET(SUNXI_CCI_SLAVE_A15)
#define SUNXI_CCI_A7_OFFSET	CCI_SLAVE_OFFSET(SUNXI_CCI_SLAVE_A7)

#define SUNXI_CCU_PHYS_BASE     (0x06000000)
#define SUNXI_CCU_C0_CFG_OFFSET (0x54)
#define SUNXI_CCU_C1_CFG_OFFSET (0x58)

FUNC sunxi_secondary_fixup , :
UNWIND(	.fnstart)
	mrc	p15, 0, r0, c0, c0, 5	/* MPIDR   */
	ubfx	r0, r0, #8, #4		/* cluster */
	
	ldr	r3, =SUNXI_CCU_PHYS_BASE + SUNXI_CCU_C0_CFG_OFFSET
	cmp	r0, #0		    /* A7 cluster? */
	addne	r3, r3, #SUNXI_CCU_C1_CFG_OFFSET - SUNXI_CCU_C0_CFG_OFFSET
	ldr	r1, [r3]
	bic     r1, r1, #(0x3<<8)   /* a15 atb div                            */
	orr     r1, r1, #(0x1<<8)   /* div = 2                                */
	bic     r1, r1, #(0x7<<0)   /* a15 atb div                            */
	orr     r1, r1, #(0x2<<0)   /* div = value + 1                        */
	str	r1, [r3]	    /* set atb div to 2, axi div to 3         */
	dsb                         /* Synchronise side-effects of axi config */
	ldr	r1, [r3]
	bic     r1, r1, #(0x3<<8)   /* a15 atb div                            */
	orr     r1, r1, #(0x2<<8)   /* div = 4                                */
	bic     r1, r1, #(0x7<<0)   /* a15 atb div                            */
	orr     r1, r1, #(0x3<<0)   /* div = value + 1                        */
	str	r1, [r3]	    /* set atb div to 4, axi div to 4         */
	dsb                         /* Synchronise side-effects of axi config */
	
	/* Enable CCI snoops. */
	ldr	r3, =SUNXI_CCI_PHYS_BASE + SUNXI_CCI_A7_OFFSET
	cmp	r0, #0		/* A7 cluster? */
	addne	r3, r3, #SUNXI_CCI_A15_OFFSET - SUNXI_CCI_A7_OFFSET

	@ r3 now points to the correct CCI slave register block
	ldr	r1, [r3, #SLAVE_SNOOPCTL_OFFSET]
	orr	r1, r1, #SNOOPCTL_SNOOP_ENABLE
	orr	r1, r1, #SNOOPCTL_DVM_ENABLE
	str	r1, [r3, #SLAVE_SNOOPCTL_OFFSET]	/* enable CCI snoops */

	/* Wait for snoop control change to complete */
	ldr	r3, =SUNXI_CCI_PHYS_BASE
1:
        ldr	r1, [r3, #CCI_STATUS_OFFSET]
	tst	r1, #STATUS_CHANGE_PENDING
	bne	1b
	dsb                             /* Synchronise side-effects of enabling CCI */

	cmp	r0, #1                  /* A15 cluster ?  */
	bne     2f
	
	/* a80 platform-specific Cortex-A15 setup */
	mrc p15, 1, r1, c15, c0, 4      /* ACTLR2 */
	orr r1, r1, #(0x1<<31)          /* Enable CPU regional clock gates */
	mcr p15, 1, r1, c15, c0, 4
	
	mrc p15, 1, r1, c15, c0, 0      /* L2ACTLR */
	orr r1, r1, #(0x1<<26)          /* Enables L2, GIC, and Timer regional clock gates */
	mcr p15, 1, r1, c15, c0, 0
	
	mrc p15, 1, r1, c15, c0, 0      /* L2ACTLR */
	orr r1, r1, #(0x1<<3)           /* Disables clean/evict from being pushed to external */
	mcr p15, 1, r1, c15, c0, 0

	mrc p15, 1, r1, c9, c0, 2
	bic r1, r1, #(0x7<<0)           /* L2 data ram latency */
	orr r1, r1, #(0x3<<0)
	mcr p15, 1, r1, c9, c0, 2

2:
        /* a80 platform-specific operations porcess done. */
	bx	lr
UNWIND(	.fnend)
END_FUNC sunxi_secondary_fixup
