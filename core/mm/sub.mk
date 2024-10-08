srcs-y += mobj.c
srcs-y += fobj.c
cflags-fobj.c-$(CFG_CORE_PAGE_TAG_AND_IV) := -Wno-missing-noreturn
srcs-y += file.c
srcs-y += vm.c
srcs-y += core_mmu.c
srcs-y += pgt_cache.c
srcs-y += tee_mm.c
srcs-y += phys_mem.c
ifneq ($(CFG_CORE_FFA),y)
srcs-$(CFG_CORE_DYN_SHM) += mobj_dyn_shm.c
endif
srcs-$(CFG_BOOT_MEM) += boot_mem.c
