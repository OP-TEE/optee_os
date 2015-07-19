# These files implements the__aeabi functions we need instead of
# relying on libgcc or equivalent as we need implementations suitable
# for bare metal.
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_divmod_a32.S
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_divmod.c
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_ldivmod_a32.S
srcs-$(CFG_ARM32_$(sm)) += arm32_aeabi_ldivmod.c
