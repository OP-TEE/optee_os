srcs-y += attestation.c

gensrcs-y += att_pta_sig_key
produce-att_pta_sig_key = signing_key.c
depends-att_pta_sig_key = $(CFG_ATTESTATION_PTA_SIGN_KEY) scripts/pem_to_c.py
recipe-att_pta_sig_key = $(PYTHON3) scripts/pem_to_c.py \
	--prefix pta_attestation_key --key $(CFG_ATTESTATION_PTA_SIGN_KEY) \
	--private --out $(sub-dir-out)/signing_key.c
