# Veraison Attestation PTA

This is a proof of concept for adding attestation capabilities to S-EL0 TAs and a demonstrator of an end-to-end remote attestation protocol [1] using the Veraison verifier [2].

For convenience, this PTA reuses the PSA token format [3]. However, note that PSA semantics do not fully apply, as many relevant properties required by the PSA SM [4] are not met.

Furthermore, the attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no way to establish trust in the PTA in the first place.

For these reasons, the PTA should not be regarded as a best practice example for real-world attestation.

Instead, this PTA aims to demonstrate the integration of various libraries and tools to create a trusted application focused on attestation within the OP-TEE environment and to practically explore an end-to-end remote attestation flow using this approach.

## Signing key

By default the PTA signs the evidence with a test key embedded at build time (`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y`). Its private key is public, so that evidence proves nothing about the device.

The caller can supply the signing key instead, as the optional fourth parameter of `PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE`: the public key coordinates X and Y (32 bytes each) followed by the private key. The private key is either the plain P-256 scalar, meant for development since it crosses into the PTA in plain on every call, or a CAAM black key in its serialized form. The PTA checks that the public key belongs to the private key, and derives the PSA instance-id of the evidence from the public key of the key in use, `0x01 || SHA-256(0x04 || X || Y)` as the PSA token profile defines it for the IAK [3]. This is what the verifier registers for the device. The caller keeps the key and is trusted to hand over the right one. The PTA stores nothing.

On i.MX with the CAAM ECC driver (`CFG_NXP_CAAM_ECC_DRV=y`, which `CFG_CRYPTO_DRIVER=y` enables together with `CFG_NXP_CAAM=y`) two commands produce such a black key: `PTA_VERAISON_ATTESTATION_GENERATE_KEYPAIR` generates the key in the CAAM and returns its public key and the serialized black key, and `PTA_VERAISON_ATTESTATION_CONVERT_TO_BLACKKEY` wraps a plain private key generated elsewhere into the same form. A serialized black key is a CAAM blob: the CAAM unwraps it inside the CAAM when signing, so signing never needs the plain private key outside the CAAM, and the blob only unwraps on the device that made it. The blob is bound to the device only while the CAAM runs in its secure state, that is on a closed device booted through the HAB secure boot. A blob made before the device was closed does not unwrap afterwards, so generate the key on the closed device. Without the CAAM ECC driver the two commands return `TEE_ERROR_NOT_SUPPORTED` and a serialized black key cannot be used.

## Known Limitations

1. **PSA Semantics Limitations:** Although this PTA reuses the PSA token format, many of the relevant properties required by the PSA Security Model (SM) are not met. This can impact the effectiveness and security assumptions typically expected from PSA-based attestation.

2. **Lack of Trust in the PTA:** The attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no mechanism to establish trust in the PTA itself from a lower-level entity, such as the bootloader. Without such anchoring to a platform Root of Trust (RoT), the PTA lacks foundational trust, which weakens the overall chain of trust.

## References

[1] https://datatracker.ietf.org/doc/rfc9334
[2] https://github.com/veraison/services
[3] https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token
[4] https://www.psacertified.org/app/uploads/2021/12/JSADEN014_PSA_Certified_SM_V1.1_BET0.pdf
