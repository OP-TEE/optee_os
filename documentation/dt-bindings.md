## Secure World OP-TEE DT bindings

OP-TEE has a formal DT binding at

```
	firmware {
		optee {
		};
	};
```

The Linux kernel device tree bindings documentation
explains the properties that may appear there that
are of interest to Normal World.

OP-TEE may also be passed a DTB at boot-time, which
may be different to, or modified from, the DTB passed
to Normal World.

The following properties inside /firmware/optee are
understood by OP-TEE itself in the Secure World.

### secure-device-id

This allows the bootloader to declare an array of bytes
which OP-TEE will use as the Secure Device ID.  For
example OP-TEE uses this information to produce the
key used for Secure Storage on that device.

Since almost no SoC has public documentation on how to
read the real device key data from e-fuses, this allows
alternate ways to get per-device stable identity bits,
eg, read the eMMC CID serial number on the same board.

This may produce less data than a real key on the SoC,
but it is still very useful since it requires no
configuration to get a unique number.

1) The secure-device-id property

The bootloader adds this, which contains a byte array
of arbitrary length.  If present, and there is no
SoC platform implementation to get the real SoC key
data, OP-TEE will take up to 160 bytes from the
property for use as the Device ID.

Example secure-device-id property

```
	firmware {
		optee {
			secure-device-id = [01 23 34 56];
		};
	};
```
