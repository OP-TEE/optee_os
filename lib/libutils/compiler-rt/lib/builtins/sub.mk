cppflags-y += -D__ARM_EABI__=$(if $(filter y,$(CFG_ARM32_$(sm))),1,0)
cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-missing-prototypes
cflags-y += -Wno-missing-declarations

srcs-y += ashlti3.c
srcs-y += udivmodti4.c
srcs-y += udivti3.c
