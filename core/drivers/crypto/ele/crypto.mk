ifeq ($(CFG_IMX_ELE),y)
CFG_IMX_ELE_ECC_DRV ?= n
CFG_IMX_ELE_ECC_DRV_FALLBACK ?= $(CFG_IMX_ELE_ECC_DRV)

CFG_CRYPTO_DRIVER ?= $(CFG_IMX_ELE_ECC_DRV)

ifeq ($(CFG_CRYPTO_DRIVER),y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0
endif # CFG_CRYPTO_DRIVER

# Issues in the ELE FW prevent OPTEE and Kernel from using
# the RNG concurrently at runtime. To prevent any issue,
# use the software RNG instead in OPTEE.
# But with Kernel ELE driver disabled, Runtime ELE RNG
# generation can be done.
CFG_WITH_SOFTWARE_PRNG ?= y

endif # CFG_IMX_ELE
