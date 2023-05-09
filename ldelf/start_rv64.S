/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright  2022  Beijing ESWIN Computing Technology Co., Ltd.
 */

#include <asm.S>
#include <elf_common.h>

/*
 * _ldelf_start() - Entry of ldelf
 *
 * See include/ldelf.h for details on TEE Core interaction.
 *
 * void _ldelf_start(struct ldelf_arg *arg);
 */
FUNC _ldelf_start , :
	/*
	 * First ldelf needs to be relocated. The binary is compiled to
	 * contain only a minimal number of R_RISCV_RELATIVE relocations in
	 * read/write memory, leaving read-only and executable memory
	 * untouched.
	 */
	lla	a1, reloc_end_rel
	lw	a3, 0(a1)
	lla	a1, reloc_begin_rel
	lw	a2, 0(a1)
	add	a2, a2, a1
	add	a3, a3, a1
	beq	a2, a3, 2f

	lla	a1, _ldelf_start	/* Get the load offset */

	/* Loop over the relocations (Elf64_Rela) and process all entries */
1:
	ld	t1, 0(a2)	/* t1 = r_offset */
	ld	t2, 8(a2)	/* t2 = r_info */
	ld	t3, 16(a2)	/* t3 = r_addend */
	addi	a2, a2, 24
	and	t2, t2, 0xff
	addi	t4, zero, R_RISCV_RELATIVE
	bne	t2, t4, 3f

	/* Update the pointer at r_offset + load offset */
	add	t1, a1, t1
	ld	t4, 0(t1)
	add	t4, t4, t3
	add	t4, t4, a1
	sd	t4, 0(t1)
	ble	a2, a3, 1b
2:
	jal	ldelf
	addi	a0, a0, 0
	jal	_ldelf_return
3:
	addi	a0, a0, 0
	jal	_ldelf_panic
reloc_begin_rel:
    .word __reloc_begin - reloc_begin_rel
reloc_end_rel:
    .word __reloc_end - reloc_end_rel
END_FUNC _ldelf_start
