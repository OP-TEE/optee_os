srcs-y += mobj.c
srcs-y += fobj.c
cflags-fobj.c-$(CFG_CORE_PAGE_TAG_AND_IV) := -Wno-missing-noreturn
srcs-y += file.c
srcs-y += vm.c
