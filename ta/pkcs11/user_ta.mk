user-ta-uuid := fd02c9da-306c-48c7-a49c-bbd827ae86ee

all: pkcs11-ta-verify-helpers

.PHONY: pkcs11-ta-verify-helpers
pkcs11-ta-verify-helpers:
	@$(cmd-echo-silent) '  CHK    ' $@
	${q}ta/pkcs11/scripts/verify-helpers.sh --quiet
