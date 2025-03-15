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
srcs-$(call cfg-one-enabled,CFG_TA_SANITIZE_UNDEFINED \
			    CFG_CORE_SANITIZE_UNDEFINED) += ubsan.c
cflags-remove-ubsan.c-$(call cfg-one-enabled,CFG_TA_SANITIZE_UNDEFINED \
					     CFG_CORE_SANITIZE_UNDEFINED)\
					     += -fsanitize=undefined
ifneq (,$(filter ta_%,$(sm)))
srcs-y += pthread_stubs.c
endif

subdirs-y += arch/$(ARCH)
subdirs-y += ftrace
