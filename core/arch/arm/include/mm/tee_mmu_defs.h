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
#ifndef TEE_MMU_DEFS_H
#define TEE_MMU_DEFS_H

#ifndef CFG_WITH_LPAE
/*
 *        The selecting between ttbr0 and ttbr1
 * TTBCR.N  |  First Address with TTBR1 |  TTBR0 table size | Index Range
 * 0b000    |    TTBR1 not used         |       16KB        | VA[31:20]
 * 0b001    |    0x80000000             |       8KB         | VA[30:20]
 * 0b010    |    0x40000000             |       4KB         | VA[29:20]
 * 0b011    |    0x20000000             |       2KB         | VA[28:20]
 * 0b100    |    0x10000000             |       1KB         | VA[27:20]
 * 0b101    |     0x8000000             |       512B        | VA[26:20]
 * 0b110    |     0x4000000             |       256B        | VA[25:20]
 * 0b111    |     0x2000000             |       128B        | VA[24:20]
 *
 * we use TTBR0 as the user space ttbr and TTBR1 as the kernel space in op-tee
 * so the TTBCR.N value determines the address space partition as above.
 * By default TTBCR.N is set to 7, which means 0~32MB(user) and 32MB~4G(kernel)
 * Note: TTBCR.N can't be set to 0
 */

/* Defined to the smallest possible secondary L1 MMU table */
#define TEE_MMU_TTBCR_N_VALUE		7

/* Number of sections in ttbr0 when user mapping activated */
#define TEE_MMU_UL1_NUM_ENTRIES         (1 << (12 - TEE_MMU_TTBCR_N_VALUE))

#define TEE_MMU_UL1_SIZE	(TEE_MMU_UL1_NUM_ENTRIES * sizeof(uint32_t))
#define TEE_MMU_UL1_ALIGNMENT	TEE_MMU_UL1_SIZE
#endif

/*
 * kmap works in common mapping starting at virtual address just above the
 * per CPU user mapping. kmap has 32 MiB of virtual address space.
 */
#define TEE_MMU_KMAP_START_VA		(32 * 1024 * 1024)
#define TEE_MMU_KMAP_END_VA		(64 * 1024 * 1024)


#define TEE_MMU_L1_NUM_ENTRIES		(TEE_MMU_L1_SIZE / 4)
#define TEE_MMU_L1_SIZE			(1 << 14)
#define TEE_MMU_L1_ALIGNMENT		TEE_MMU_L1_SIZE

#define TEE_MMU_L2_NUM_ENTRIES		(TEE_MMU_L2_SIZE / 4)
#define TEE_MMU_L2_SIZE			(1 << 10)
#define TEE_MMU_L2_ALIGNMENT		TEE_MMU_L2_SIZE

/* TTB attributes */

/* TTB0 of TTBR0 (depends on TEE_MMU_TTBCR_N_VALUE) */
#define TEE_MMU_TTB_UL1_MASK	(~(TEE_MMU_UL1_ALIGNMENT - 1))
/* TTB1 of TTBR1 */
#define TEE_MMU_TTB_L1_MASK	(~(TEE_MMU_L1_ALIGNMENT - 1))

#endif /* TEE_MMU_DEFS_H */
