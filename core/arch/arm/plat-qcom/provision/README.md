# Fuse provisioning

At boot, OP-TEE can program fuses from data left in a memory window by an
earlier boot stage. The window is `CFG_SEC_ELF_DDR_ADDR` /
`CFG_SEC_ELF_DDR_SIZE`. The loader (`provision_boot.c`) copies it, clears it,
programs the fuses and panics on any failure.

## Building blocks

| File | Role |
|---|---|
| `provision_core.c` | Engine: runs the passes of a format, writes a region |
| `provision_backend.h` | Fuse access used by the engine |
| `provision_backend_qfprom.c` | Backend using the memory mapped fuse driver |
| `provision_backend_tme.c` | Backend using the security processor |
| `sec_elf_v2.c`, `provision_v2.c`, `provision_regions.c` | Segmented format (rev 2) |
| `sec_elf_v3.c`, `provision_v3.c` | Flat format (rev 3) |
| `provision_arb.c` | Anti-rollback commit |

## Configuration

| Switch | Default | Meaning |
|---|---|---|
| `CFG_QCOM_QFPROM_FUSEPROV` | target | Build the feature |
| `CFG_QCOM_PROVISION_BACKEND` | `qfprom` | `qfprom` or `tme` |
| `CFG_QCOM_PROVISION_SEC_ELF_V3` | `n` | Flat format; needs backend `tme` |
| `CFG_QCOM_PROVISION_BUFFER_AUTHENTICATED` | `n` | Required by the flat format, which has no hash or signature: the window must be secure memory authenticated before OP-TEE runs |
| `CFG_QCOM_TME_ARB` | `n` | Commit the anti-rollback state before programming; needs backend `tme` |

The `tme` backend needs `CFG_CORE_EL3_SPMC=y`, and runs at the late driver
initcall level because the FF-A communication service is not up earlier.
It reads the corrected view of a row only.

## Behaviour

- Skipped in download mode.
- An absent or invalid magic means there is nothing to program.
- Programming stops at the first failure; the window is cleared on every
  exit, and with the `tme` backend also right after it was copied.
- Only row addresses are logged, never fuse values.
- Reading is done in the corrected space. Row skip rules and FEC handling
  differ between the two formats and are not shared on purpose.

## Not covered

The message exchange with the security processor, real fuse writes and the
anti-rollback semantics could not be tested without hardware. The platform
must provide the download mode register, and optionally the write permission
row (`PROVISION_WRITE_PERM_ADDR` / `PROVISION_WRITE_PERM_MASK`) for the lock
check.
