subdirs-$(CFG_QCOM_PAS_PTA) += pas

# Exposes qfprom-backed fuse reads to user TAs.
CFG_QCOM_FUSE_PTA ?= n
subdirs-$(CFG_QCOM_FUSE_PTA) += fuse

# Programs software keys into Inline Crypto Engine (ICE) key slots for
# inline storage encryption.
CFG_QCOM_ICE_PTA ?= n
subdirs-$(CFG_QCOM_ICE_PTA) += ice
