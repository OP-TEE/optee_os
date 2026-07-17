user-ta-uuid := cff7d191-7ca0-4784-af13-48223b9a4fbe

# The metadata blob passed at INIT_IMAGE is ELF hdr + phdr table + hash
# segment - up to ~400 KB for the larger DSP images. Set the heap large
# enough to hold a full copy plus working room when CFG_QCOM_PAS_AUTH is
# enabled; otherwise keep the small default.
ifeq ($(CFG_QCOM_PAS_AUTH),y)
CFG_PAS_TA_HEAP_SIZE ?= (512 * 1024)
else
CFG_PAS_TA_HEAP_SIZE ?= (4 * 1024)
endif

# Authenticate each PIL firmware image on INIT_IMAGE: verify the per-segment
# hash table against the loaded firmware, and (on devices with secure-boot
# fuses blown) validate the image's certificate chain, signature and
# fuse-bound bindings before releasing the peripheral from reset. Disable
# on configurations where the TA is not responsible for image
# authentication.
CFG_QCOM_PAS_AUTH ?= n
