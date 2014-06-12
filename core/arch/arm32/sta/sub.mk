srcs-y += sta_helloworld.c
cflags-sta_helloworld.c-y += -Wno-unused-parameter

srcs-y += core_dirty_tests.c
cflags-core_dirty_tests.c-y += -Wno-format
cflags-core_dirty_tests.c-y += -Wno-format-nonliteral -Wno-format-security
