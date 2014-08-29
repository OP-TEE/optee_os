srcs-y += core_mmu.c
cflags-core_mmu.c-y += -Wno-strict-aliasing -Wno-unused-parameter

srcs-y += tee_pager_unpg.c
cflags-tee_pager_unpg.c-y += -Wno-unused-parameter


srcs-y += tee_mmu.c
cflags-tee_mmu.c-y += -Wno-unused-parameter

srcs-y += kta_table_unpg_asm.S
srcs-y += tee_mm.c
cflags-tee_mm.c-y += -Wno-format
cflags-tee_mm.c-y += -Wno-format-nonliteral -Wno-format-security

srcs-y += tee_mm_unpg.c
srcs-y += tee_mmu_unpg_asm.S
srcs-y += tee_mmu_unpg.c
srcs-y += tee_pager.c
srcs-y += tee_pager_unpg_asm.S
