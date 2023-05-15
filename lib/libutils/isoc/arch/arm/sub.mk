# These files implements the__aeabi functions we need instead of
# relying on libgcc or equivalent as we need implementations suitable
# for bare metal.
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_divmod_a32.S
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_divmod.c
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_ldivmod_a32.S
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_ldivmod.c
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_shift.c

ifeq ($(CFG_ULIBS_MCOUNT),y)
# We would not like to profile __aeabi functions as these provide
# internal implementations for "/ %" operations. Also, "/ %" operations
# could be used inside profiling code which could create an incorrect
# cyclic behaviour.
cflags-remove-arm32_aeabi_divmod.c-y += -pg
cflags-remove-arm32_aeabi_ldivmod.c-y += -pg
cflags-remove-arm32_aeabi_shift.c-y += -pg
endif

srcs-$(CFG_ARM32_$(sm)) += setjmp_a32.S
srcs-$(CFG_ARM64_$(sm)) += setjmp_a64.S

ifeq ($(CFG_TA_FLOAT_SUPPORT),y)
# Floating point is only supported for user TAs
ifneq ($(sm),core)
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_softfloat.c
cflags-arm32_aeabi_softfloat.c-y += -Wno-aggregate-return
cflags-arm32_aeabi_softfloat.c-y += -Wno-missing-prototypes
cflags-arm32_aeabi_softfloat.c-y += -Wno-missing-declarations
subdirs-$(CFG_ARM32_$(sm)) += softfloat
endif
endif
