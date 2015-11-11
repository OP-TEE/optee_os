ifeq ($(CFG_ARM64_$(sm)),y)
$(sm)-platform-cppflags += -DARM64=1 -D__LP64__=1
endif
ifeq ($(CFG_ARM32_$(sm)),y)
$(sm)-platform-cppflags += -DARM32=1 -D__ILP32__=1
endif
