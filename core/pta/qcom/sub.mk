subdirs-$(CFG_QCOM_PAS_PTA) += pas

# Exposes qfprom-backed fuse reads to user TAs.
CFG_QCOM_FUSE_PTA ?= n
subdirs-$(CFG_QCOM_FUSE_PTA) += fuse

# Exposes sec.elf fuse provisioning through TME-Lite to the REE.
subdirs-$(CFG_QCOM_TMEL_FUSEPROV) += fuseprov
