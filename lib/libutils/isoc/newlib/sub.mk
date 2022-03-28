cflags-y += -Wno-sign-compare
cflags-y += -Wno-parentheses
cflags-remove-y += -Wcast-align

srcs-y += abs.c
srcs-y += bcmp.c
srcs-y += memchr.c
srcs-y += memcmp.c
srcs-y += memcpy.c
ifeq (s,$(CFG_CC_OPT_LEVEL))
cflags-memcpy.c-y += -O2
endif
cflags-memcpy.c-y += $(call cc-option,-fno-tree-loop-distribute-patterns)
srcs-y += memmove.c
cflags-memmove.c-y += $(call cc-option,-fno-tree-loop-distribute-patterns)
srcs-y += memset.c
cflags-memset.c-y += $(call cc-option,-fno-tree-loop-distribute-patterns)
srcs-y += strchr.c
srcs-y += strcmp.c
srcs-y += strcpy.c
srcs-y += strlen.c
srcs-y += strncmp.c
srcs-y += strncpy.c
srcs-y += strnlen.c
srcs-y += strrchr.c
srcs-y += strstr.c
srcs-y += strtoul.c
srcs-y += strtok_r.c
