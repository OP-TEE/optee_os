cppflags-y += -D__ARM_EABI__=$(if $(filter y,$(CFG_ARM32_$(sm))),1,0)
cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-missing-prototypes
cflags-y += -Wno-missing-declarations

srcs-y += ashlti3.c
srcs-y += mulodi4.c
srcs-y += udivmodti4.c
srcs-y += udivti3.c

# The 64-bit integer routines GCC calls on 32-bit RISC-V, and the
# routines they call. ARM32 has its own in lib/libutils/isoc/arch/arm.
srcs-$(CFG_RV32_$(sm)) += ashldi3.c
srcs-$(CFG_RV32_$(sm)) += ashrdi3.c
srcs-$(CFG_RV32_$(sm)) += clzdi2.c
srcs-$(CFG_RV32_$(sm)) += clzsi2.c
srcs-$(CFG_RV32_$(sm)) += ctzsi2.c
srcs-$(CFG_RV32_$(sm)) += divdi3.c
srcs-$(CFG_RV32_$(sm)) += lshrdi3.c
srcs-$(CFG_RV32_$(sm)) += moddi3.c
srcs-$(CFG_RV32_$(sm)) += udivdi3.c
srcs-$(CFG_RV32_$(sm)) += udivmoddi4.c
srcs-$(CFG_RV32_$(sm)) += umoddi3.c
