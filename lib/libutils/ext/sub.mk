global-incdirs-y += include

srcs-y += snprintk.c
srcs-y += strlcat.c
srcs-y += strlcpy.c
srcs-y += buf_compare_ct.c
srcs-y += trace.c
srcs-y += mempool.c

subdirs-$(arch_arm) += arch/$(ARCH)
