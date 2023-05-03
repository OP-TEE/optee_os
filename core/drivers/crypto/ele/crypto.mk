ifeq ($(CFG_IMX_ELE),y)

# Issues in the ELE FW prevent OPTEE and Kernel from using
# the RNG concurrently at runtime. To prevent any issue,
# use the software RNG instead in OPTEE.
# But with Kernel ELE driver disabled, Runtime ELE RNG
# generation can be done.
CFG_WITH_SOFTWARE_PRNG ?= y
endif # CFG_IMX_ELE
