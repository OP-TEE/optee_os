subdirs-$(CFG_QCOM_PAS_PTA) += pas

# Exposes qfprom-backed fuse reads to user TAs.
CFG_QCOM_FUSE_PTA ?= n
subdirs-$(CFG_QCOM_FUSE_PTA) += fuse
