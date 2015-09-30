# this script defines platform specific settings for TEE armv7 build

ifeq ($(PLATFORM_FLAVOR),cannes)

# Static configuration of DDR reserved to TEE/TZ
# Provide here only start address and size. TEEcore will adapt.
# Allow these settings to be overridden.
CFG_DDR_TEETZ_RESERVED_START ?= 0x93a00000
CFG_DDR_TEETZ_RESERVED_SIZE ?= 0x01000000

else ifeq ($(PLATFORM_FLAVOR),orly2)

# Static configuration of DDR reserved to TEE/TZ
# Provide here only start address and size. TEEcore will adapt.
# Allow these settings to be overridden.
CFG_DDR_TEETZ_RESERVED_START ?= 0x8F000000
CFG_DDR_TEETZ_RESERVED_SIZE ?= 0x00800000

else
$(error PLATFORM_FLAVOR=$(PLATFORM_FLAVOR) is not supported)
endif

ifndef CFG_DDR_TEETZ_RESERVED_START
$(error "CFG_DDR_TEETZ_RESERVED_START should be set from system_config.in")
endif
ifndef CFG_DDR_TEETZ_RESERVED_SIZE
$(error "CFG_DDR_TEETZ_RESERVED_SIZE should be set from system_config.in")
endif
