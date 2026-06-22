/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>
#include <riscv_vector.h>


/*
 * size_t riscv_vector_state_size(void)
 * Formula: sizeof(struct riscv_vector_state) + (32 * CSR_VLENB)
 * Assuming base structure size is 16 bytes (vcsr=8 bytes + vstart=8 bytes)
 */
FUNC riscv_vector_state_size , :
    csrr    a0, CSR_VLENB           /* Fetch vector length in bytes */
    li      t0, 32
    mul     a0, a0, t0              /* a0 = 32 * vlenb */
    addi    a0, a0, 16              /* Add base structure size (vcsr + vstart) */
    ret
END_FUNC riscv_vector_state_size


/*
 * void riscv_vector_save(struct riscv_vector_state *dst)
 * Layout offsets: 0->vcsr, 8->vstart, 16->vregs
 */
FUNC riscv_vector_save , :
    beqz    a0, 1f                  /* Early exit if dst == NULL */

    /* Step 1: Save original sstatus and enable SSTATUS_VS bits */
    csrr    t1, CSR_SSTATUS         /* t1 = sstatus_orig */
    li      t0, SSTATUS_VS          /* vector state bitmask flag */
    csrs    CSR_SSTATUS, t0         /* sstatus |= SSTATUS_VS */

    /* Step 2: Save Control Registers */
    csrr    t0, CSR_VCSR
    sd      t0, 0(a0)               /* dst->vcsr = vcsr */
    csrr    t0, CSR_VSTART
    sd      t0, 8(a0)               /* dst->vstart = vstart */

    /* Step 3: Save Vector Data Registers via Unrolled Macro */
    csrr    t2, CSR_VLENB           /* t2 = vlenb */
    addi    a1, a0, 16              /* a1 = base address pointer of dst->vregs */
    do_all_vreg_chunks vs8r.v, a1, t2

    /* Step 4: Restore original sstatus context cleanly */
    csrw    CSR_SSTATUS, t1
1:
    ret
END_FUNC riscv_vector_save


/*
 * void riscv_vector_restore(const struct riscv_vector_state *src)
 */
FUNC riscv_vector_restore , :
    beqz    a0, 1f                  /* Early exit if src == NULL */

    /* Step 1: Save original sstatus and enable execution tracking safety flags */
    csrr    t1, CSR_SSTATUS         /* t1 = sstatus_orig */
    li      t0, SSTATUS_VS
    csrs    CSR_SSTATUS, t0         /* sstatus |= SSTATUS_VS */

    /* Step 2: Restore Vector Data Registers via Unrolled Macro */
    csrr    t2, CSR_VLENB           /* t2 = vlenb */
    addi    a1, a0, 16              /* a1 = base address pointer of src->vregs */
    do_all_vreg_chunks vl8r.v, a1, t2

    /* Step 3: Restore CSR registers */
    ld      t0, 0(a0)               /* t0 = src->vcsr */
    csrw    CSR_VCSR, t0
    ld      t0, 8(a0)               /* t0 = src->vstart */
    csrw    CSR_VSTART, t0

    /* Step 4: Restore original sstatus context cleanly */
    csrw    CSR_SSTATUS, t1
1:
    ret
END_FUNC riscv_vector_restore
