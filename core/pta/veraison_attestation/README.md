# Veraison Attestation PTA

This is a proof of concept for adding attestation capabilities to S-EL0 TAs and a demonstrator of an end-to-end remote attestation protocol [1] using the Veraison verifier [2].

For convenience, this PTA reuses the PSA token format [3]. However, note that PSA semantics do not fully apply, as many relevant properties required by the PSA SM [4] are not met.

Furthermore, the attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no way to establish trust in the PTA in the first place.

For these reasons, the PTA should not be regarded as a best practice example for real-world attestation.

Instead, this PTA aims to demonstrate the integration of various libraries and tools to create a trusted application focused on attestation within the OP-TEE environment and to practically explore an end-to-end remote attestation flow using this approach.

## Known Limitations

1. **PSA Semantics Limitations:** Although this PTA reuses the PSA token format, many of the relevant properties required by the PSA Security Model (SM) are not met. This can impact the effectiveness and security assumptions typically expected from PSA-based attestation.

2. **Lack of Trust in the PTA:** The attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no mechanism to establish trust in the PTA itself from a lower-level entity, such as the bootloader. Without such anchoring to a platform Root of Trust (RoT), the PTA lacks foundational trust, which weakens the overall chain of trust.

## References

[1] https://datatracker.ietf.org/doc/rfc9334
[2] https://github.com/veraison/services
[3] https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token
[4] https://www.psacertified.org/app/uploads/2021/12/JSADEN014_PSA_Certified_SM_V1.1_BET0.pdf
