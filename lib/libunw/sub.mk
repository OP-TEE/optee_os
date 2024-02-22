global-incdirs-y += include
ifeq ($(CFG_UNWIND),y)
ifeq (arm,$(ARCH))
srcs-y += unwind_arm32.c
endif
srcs-$(CFG_ARM64_$(sm)) += unwind_arm64.c
ifeq (riscv,$(ARCH))
srcs-y += unwind_riscv.c
endif
endif
