
incdirs-y += include

ifeq ($(CFG_MAILBOX_DRIVER),y)
ifeq ($(CFG_MAILBOX_LOCAL_ID),)
$(error error: CFG_MAILBOX_LOCAL_ID not set for $(PLATFORM) $(PLATFORM_FLAVOR))
endif
endif

srcs-$(CFG_MAILBOX_DRIVER) += mailbox_driver.c
