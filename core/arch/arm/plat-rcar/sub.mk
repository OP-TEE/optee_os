global-incdirs-y += .
srcs-y += main.c
srcs-$(CFG_OTP_SUPPORT) += tee_common_otp.c
srcs-y += rcar_lock.c
srcs-y += rcar_log_func.c
srcs-y += rcar_ddr_training.c
srcs-$(CFG_ARM32_core) += rcar_interruptflags_a32.S
srcs-$(CFG_ARM64_core) += rcar_interruptflags_a64.S
srcs-$(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE) += rcar_ta_auth.c
ifeq ($(CFG_DYNAMIC_TA_AUTH_BY_HWENGINE),y)
srcs-$(CFG_ARM32_core) += rcar_ta_auth_a32.S
srcs-$(CFG_ARM64_core) += rcar_ta_auth_a64.S
endif

# Copy the base file - /core/arch/arm/kernel/
srcs-y += trace_ext.c
