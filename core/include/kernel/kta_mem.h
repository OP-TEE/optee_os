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
#ifndef KTA_MEM_H
#define KTA_MEM_H

#include <stdbool.h>
#include <stdint.h>

#define TEE_MEM_SEC_ESRAM_SHIFT         0
#define TEE_MEM_SEC_CLASS0_DDR_SHIFT    2
#define TEE_MEM_SEC_CLASS1_DDR_SHIFT    4
#define TEE_MEM_DDR_SHIFT               6
#define TEE_MEM_SEC_HW_SHIFT            8
#define TEE_MEM_RES_MMU_UL1_SHIFT       10
#define TEE_MEM_MM_ESRAM_FW_SHIFT       12

/* Checking for Secure eSRAM */
#define TEE_MEM_SEC_ESRAM               (1 << TEE_MEM_SEC_ESRAM_SHIFT)
#define TEE_MEM_NOT_SEC_ESRAM           (TEE_MEM_SEC_ESRAM << 1)
/* Checking for class0 firewalled DDR */
#define TEE_MEM_SEC_CLASS0_DDR          (1 << TEE_MEM_SEC_CLASS0_DDR_SHIFT)
#define TEE_MEM_NOT_SEC_CLASS0_DDR      (TEE_MEM_SEC_CLASS0_DDR << 1)
/* Checking for class1 firewalled DDR */
#define TEE_MEM_SEC_CLASS1_DDR          (1 << TEE_MEM_SEC_CLASS1_DDR_SHIFT)
#define TEE_MEM_NOT_SEC_CLASS1_DDR      (TEE_MEM_SEC_CLASS1_DDR << 1)
/* Checking for DDR */
#define TEE_MEM_DDR                     (1 << TEE_MEM_DDR_SHIFT)
#define TEE_MEM_NOT_DDR                 (TEE_MEM_DDR << 1)
/*
 * Checking for secure resources based on ROM:ed MMU mapping with a few
 * exceptions.
 */
#define TEE_MEM_SEC_HW		(1 << TEE_MEM_SEC_HW_SHIFT)
#define TEE_MEM_NOT_SEC_HW	(TEE_MEM_SEC_HW << 1)

#define TEE_MEM_RES_MMU_UL1	(1 << TEE_MEM_RES_MMU_UL1_SHIFT)
#define TEE_MEM_NOT_RES_MMU_UL1	(TEE_MEM_RES_MMU_UL1 << 1)
#define TEE_MEM_MM_ESRAM_FW	(1 << TEE_MEM_MM_ESRAM_FW_SHIFT)
#define TEE_MEM_NOT_MM_ESRAM_FW	(TEE_MEM_MM_ESRAM_FW << 1)

/* Buffer is non secure, writing to it can't compromise security */
#define TEE_MEM_NON_SEC		(TEE_MEM_NOT_SEC_ESRAM | \
				TEE_MEM_NOT_SEC_CLASS0_DDR | \
				TEE_MEM_NOT_SEC_CLASS1_DDR | \
				TEE_MEM_NOT_SEC_HW | \
				TEE_MEM_NOT_MM_ESRAM_FW)

/* Buffer is secure, data can't be accessed by normal world */
#define TEE_MEM_SEC		(TEE_MEM_SEC_ESRAM | TEE_MEM_SEC_CLASS0_DDR)

/* IO access macro */
#define  IO(addr)  (*((volatile unsigned long *)(addr)))

#endif /* KTA_MEM_H */
