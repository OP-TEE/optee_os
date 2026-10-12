# Veraison Attestation PTA

This is a proof of concept for adding attestation capabilities to S-EL0 TAs and a demonstrator of an end-to-end remote attestation protocol [1] using the Veraison verifier [2].

For convenience, this PTA reuses the PSA token format [3]. However, note that PSA semantics do not fully apply, as many relevant properties required by the PSA SM [4] are not met.

Furthermore, the attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no way to establish trust in the PTA in the first place.

For these reasons, the PTA should not be regarded as a best practice example for real-world attestation.

Instead, this PTA aims to demonstrate the integration of various libraries and tools to create a trusted application focused on attestation within the OP-TEE environment and to practically explore an end-to-end remote attestation flow using this approach.

## Signing key

By default the PTA signs with a test key embedded at build time
(`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y`). With
`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=n` the PTA owns its signing key:
an ECDSA P-256 key generated on first use and kept in the private secure
storage of the PTA (`CFG_REE_FS=y` or `CFG_RPMB_FS=y`). The key never
leaves the PTA. `PTA_VERAISON_ATTESTATION_GET_PUBLIC_KEY` returns its
public key, which is what the verifier registers for the device;
`PTA_VERAISON_ATTESTATION_IMPORT_KEY` installs a key generated and
registered elsewhere, for a provisioning flow, and only works while the
PTA has no key yet. A key, once stored, is never replaced: it is the key
of every TA's evidence, so no TA may change it under the others, and the
store never has to swap an object in place, which not every file system
does atomically. Rotating the key means wiping the object from the secure
storage of the PTA, restarting the TEE, since the PTA keeps the key in
memory once it has read it, and provisioning again. Only user TAs can
open a session with the PTA, so a client in the normal world cannot
provision the key either. The PSA instance-id of the token is derived
from the public key of the key in use, as described in [3].

On i.MX with the CAAM ECC driver (`CFG_NXP_CAAM_ECC_DRV=y`, which
`CFG_CRYPTO_DRIVER=y` enables together with `CFG_NXP_CAAM=y`) the stored
key is a CAAM black key wrapped in a CAAM blob: the CAAM unwraps it inside
the CAAM when signing, so the plain private key never exists in memory,
and the blob only unwraps on the device that made it. The blob is bound
to the device only while the CAAM runs in its secure state, that is on a
closed device booted through the HAB secure boot; on an open device the
CAAM wraps with a test master key, so a key generated there is neither
device specific nor usable once the device is closed. Generate or import
the key after closing the device.

## Platform claims

With `CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS=y` the security
lifecycle and the signer of the boot images come from the platform
instead of fixed test values. This is implemented for the i.MX 8M family
(`CFG_MX8M=y` with `CFG_IMX_OCOTP=y`), following the fuses NXP's U-Boot
reads to tell whether the HAB secure boot is in force: no SRK hash is
"assembly and test", an SRK hash on an open device is "PSA RoT
provisioning", a closed device is "secured" and a closed device put in the
field return state is "decommissioned". The boot signer is the SRK hash,
in the byte order of the `srktool` efuse file.

## Software component

The evidence carries one software component, the calling TA. Its
measurement value is the SHA-256 of the read-only memory of the TA. Its
signer-id is the SHA-256 of the TA root public key the core verifies TAs
against (`ta_pub_key`), over the big-endian modulus followed by the
big-endian 32-bit exponent; for a key with the usual exponent 65537 it
can be computed from the key file the core was built with:

```sh
openssl rsa -in keys/default_ta.pem -noout -modulus | cut -d= -f2 | \
    tr -d '\n' | sed 's/$/00010001/' | xxd -r -p | sha256sum
```

An early TA is part of the core image and carries no signature of its
own, so its signer-id is the boot signer: the SRK hash with the platform
claims, a fixed test value otherwise.

## Known Limitations

1. **PSA Semantics Limitations:** Although this PTA reuses the PSA token format, many of the relevant properties required by the PSA Security Model (SM) are not met. This can impact the effectiveness and security assumptions typically expected from PSA-based attestation.

2. **Lack of Trust in the PTA:** The attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no mechanism to establish trust in the PTA itself from a lower-level entity, such as the bootloader. Without such anchoring to a platform Root of Trust (RoT), the PTA lacks foundational trust, which weakens the overall chain of trust. A signing key the PTA keeps for itself, a CAAM black key on i.MX, and the fuse-derived lifecycle tie the evidence to the device and to its secure boot configuration, but they do not measure the PTA or OP-TEE itself.

## References

[1] https://datatracker.ietf.org/doc/rfc9334
[2] https://github.com/veraison/services
[3] https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token
[4] https://www.psacertified.org/app/uploads/2021/12/JSADEN014_PSA_Certified_SM_V1.1_BET0.pdf
