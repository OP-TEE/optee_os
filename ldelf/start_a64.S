/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <asm.S>
#include <elf_common.h>

/*
 * _start() - Entry of ldelf
 *
 * See include/ldelf.h for details on TEE Core interaction.
 *
 * void start(struct ldelf_arg *arg);
 */
FUNC _ldelf_start , :
	/*
	 * First ldelf needs to be relocated. The binary is compiled to
	 * contain only a minimal number of R_AARCH64_RELATIVE relocations
	 * in read/write memory, leaving read-only and executeble memory
	 * untouched.
	 */
	adr	x4, reloc_begin_rel
	ldr	w5, reloc_begin_rel
	ldr	w6, reloc_end_rel
	add	x5, x5, x4
	add	x6, x6, x4
	cmp	x5, x6
	beq	2f

	adr	x4, _ldelf_start	/* Get the load offset */

	/* Loop over the relocations (Elf64_Rela) and process all entries */
1:	ldp	x7, x8, [x5], #16	/* x7 = r_offset, x8 = r_info */
	ldr	x9, [x5], #8		/* x9 = r_addend */
	and	x8, x8, #0xffffffff
	cmp	x8, #R_AARCH64_RELATIVE
	/* We're currently only supporting R_AARCH64_RELATIVE relocations */
	bne	3f

	/*
	 * Update the pointer at r_offset + load_offset with r_addend +
	 * load_offset.
	 */
	add	x7, x7, x4
	add	x9, x9, x4
	str	x9, [x7]

	cmp	x5, x6
	blo	1b

2:	bl	ldelf
	mov	x0, #0
	bl	_ldelf_return
3:	mov	x0, #0
	bl	_ldelf_panic
reloc_begin_rel:
    .word __reloc_begin - reloc_begin_rel
reloc_end_rel:
    .word __reloc_end - reloc_end_rel
END_FUNC _ldelf_start
