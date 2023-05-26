global-incdirs-y += include
ifeq ($(CFG_UNWIND),y)
srcs-y += unwind_arm32.c
srcs-$(CFG_ARM64_$(sm)) += unwind_arm64.c
ifneq (,$(filter y,$(CFG_RV32_$(sm)) $(CFG_RV64_$(sm))))
srcs-y += unwind_riscv.c
endif
endif
