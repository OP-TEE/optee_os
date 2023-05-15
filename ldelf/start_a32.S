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
	 * contain only a minimal number of R_ARM_RELATIVE relocations in
	 * read/write memory, leaving read-only and executeble memory
	 * untouched.
	 */
	adr	r4, reloc_begin_rel
	ldr	r5, reloc_begin_rel
	ldr	r6, reloc_end_rel
	add	r5, r5, r4
	add	r6, r6, r4
	cmp	r5, r6
	beq	2f

	adr	r4, _ldelf_start	/* Get the load offset */

	/* Loop over the relocations (Elf32_Rel) and process all entries */
1:	ldmia	r5!, {r7-r8} /* r7 == r_offset, r8 = r_info */
	and	r8, r8, #0xff
	cmp	r8, #R_ARM_RELATIVE
	/* We're currently only supporting R_ARM_RELATIVE relocations */
	bne	3f

	/* Update the pointer at r_offset + load_offset */
	add	r7, r7, r4
	ldr	r8, [r7]
	add	r8, r8, r4
	str	r8, [r7]

	cmp	r5, r6
	blo	1b

2:	bl	ldelf
	mov	r0, #0
	bl	_ldelf_return
3:	mov	r0, #0
	bl	_ldelf_panic
reloc_begin_rel:
    .word __reloc_begin - reloc_begin_rel
reloc_end_rel:
    .word __reloc_end - reloc_end_rel
END_FUNC _ldelf_start
