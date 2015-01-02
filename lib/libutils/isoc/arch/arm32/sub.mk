# These files implements the__aeabi functions we need instead of
# relying on libgcc or equivalent as we need implementations suitable
# for bare metal.
srcs-y += aeabi_divmod_asm.S
srcs-y += aeabi_divmod.c
srcs-y += aeabi_ldivmod_asm.S
srcs-y += aeabi_ldivmod.c
