ifeq ($(CFG_UNWIND),y)
srcs-$(CFG_ARM32_$(sm)) += aeabi_unwind.c
endif
srcs-$(CFG_ARM32_$(sm)) += atomic_a32.S
srcs-$(CFG_ARM64_$(sm)) += atomic_a64.S
srcs-y += auxval.c
ifneq ($(sm),ldelf) # TA, core
srcs-$(CFG_ARM32_$(sm)) += mcount_a32.S
srcs-$(CFG_ARM64_$(sm)) += mcount_a64.S
endif
