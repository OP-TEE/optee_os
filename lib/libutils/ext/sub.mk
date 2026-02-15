global-incdirs-y += include

srcs-y += snprintk.c
srcs-y += strlcat.c
srcs-y += strlcpy.c
srcs-y += trace.c
srcs-y += mempool.c
srcs-y += nex_strdup.c
srcs-y += consttime_memcmp.c
srcs-y += memzero_explicit.c
srcs-y += fault_mitigation.c
srcs-y += qsort_helpers.c
srcs-y += array.c
srcs-y += base64.c
ifneq (,$(filter y,$(CFG_CORE_SANITIZE_UNDEFINED) \
                    $(CFG_TA_SANITIZE_UNDEFINED) \
                    $(CFG_CORE_SANITIZE_KADDRESS)))
ifneq (,$(filter $(COMPILER),clang))
$(error error: UBSan/KASan not supported with Clang)
endif
endif

ifneq (,$(filter $(sm)-$(CFG_CORE_SANITIZE_UNDEFINED),core-y ldelf-y))
build-ubsan := y
endif
ifeq (,$(filter $(sm),core ldelf))
build-ubsan := $(CFG_TA_SANITIZE_UNDEFINED)
endif
srcs-$(build-ubsan) += ubsan.c
cflags-remove-ubsan.c-y += -fsanitize=undefined

ifneq (,$(filter $(sm)-$(CFG_CORE_SANITIZE_KADDRESS),core-y ldelf-y))
build-asan := y
endif
ifeq (,$(filter $(sm),core ldelf))
build-asan := $(CFG_TA_SANITIZE_KADDRESS)
endif

srcs-$(build-asan) += asan.c asan_test.c
cflags-remove-asan.c-y += $(finstrument-functions)
cflags-remove-asan.c-y += -fsanitize=kernel-address -fasan-% --param=asan-%

ifneq (,$(filter ta_%,$(sm)))
srcs-y += pthread_stubs.c
endif

subdirs-y += arch/$(ARCH)
subdirs-y += ftrace
