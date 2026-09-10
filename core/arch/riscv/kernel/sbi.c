// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022,2026 NXP
 */

#include <assert.h>
#include <riscv.h>
#include <sbi.h>
#include <stdio.h>
#include <trace.h>

/* Extensions probed once at boot by sbi_init() */
static const struct {
	unsigned long id;
	const char *name;
} sbi_exts[] = {
	{ SBI_EXT_TIME, "TIME" },
	{ SBI_EXT_IPI, "IPI" },
	{ SBI_EXT_RFENCE, "RFENCE" },
	{ SBI_EXT_HSM, "HSM" },
	{ SBI_EXT_SRST, "SRST" },
	{ SBI_EXT_PMU, "PMU" },
	{ SBI_EXT_DBCN, "DBCN" },
	{ SBI_EXT_SUSP, "SUSP" },
	{ SBI_EXT_CPPC, "CPPC" },
	{ SBI_EXT_NACL, "NACL" },
	{ SBI_EXT_STA, "STA" },
	{ SBI_EXT_SSE, "SSE" },
	{ SBI_EXT_FWFT, "FWFT" },
	{ SBI_EXT_DBTR, "DBTR" },
	{ SBI_EXT_MPXY, "MPXY" },
	{ SBI_EXT_TEE, "TEE" },
};

static unsigned long sbi_spec_version __nex_bss;
static unsigned long sbi_impl_id __nex_bss;
static unsigned long sbi_impl_version __nex_bss;
/* sbi_ext_present[n] is true when sbi_exts[n] is available */
static bool sbi_ext_present[ARRAY_SIZE(sbi_exts)] __nex_bss;

/**
 * sbi_probe_extension() - Check if an SBI extension ID is supported or not.
 * @extid: The extension ID to be probed.
 *
 * Return: 1 or an extension specific nonzero value if yes, 0 otherwise.
 */
int sbi_probe_extension(int extid)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid);
	if (!ret.error)
		return ret.value;

	return 0;
}

static unsigned long sbi_base_get(enum sbi_ext_base_fid fid)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_BASE, fid);
	if (ret.error)
		return 0;

	return ret.value;
}

/**
 * sbi_init() - Identify the SBI implementation and probe its extensions
 *
 * Called once on the primary hart before the console is initialized so
 * that every SBI user can rely on sbi_ext_available(). Only the Base
 * extension is used here, which is mandatory since SBI v0.2; a v0.1
 * firmware fails the Base calls and is recorded as v0.1 with no
 * extension available.
 */
void sbi_init(void)
{
	size_t n = 0;

	sbi_spec_version = sbi_base_get(SBI_EXT_BASE_GET_SPEC_VERSION);
	if (!sbi_spec_version) {
		sbi_spec_version = 1;	/* v0.1: no Base extension */
		return;
	}
	sbi_impl_id = sbi_base_get(SBI_EXT_BASE_GET_IMP_ID);
	sbi_impl_version = sbi_base_get(SBI_EXT_BASE_GET_IMP_VERSION);

	for (n = 0; n < ARRAY_SIZE(sbi_exts); n++)
		sbi_ext_present[n] = sbi_probe_extension(sbi_exts[n].id);
}

/**
 * sbi_print_info() - Log the SBI implementation and its extensions
 *
 * To be called once the console is up.
 */
void sbi_print_info(void)
{
	unsigned long major = sbi_spec_version >> SBI_SPEC_VERSION_MAJOR_SHIFT;
	unsigned long minor = sbi_spec_version;
	char buf[128] = { };
	size_t pos = 0;
	size_t n = 0;
	int rc = 0;

	major &= SBI_SPEC_VERSION_MAJOR_MASK;
	minor &= SBI_SPEC_VERSION_MINOR_MASK;
	IMSG("SBI v%lu.%lu, implementation ID %#lx version %#lx",
	     major, minor, sbi_impl_id, sbi_impl_version);

	for (n = 0; n < ARRAY_SIZE(sbi_exts); n++) {
		if (!sbi_ext_present[n])
			continue;
		rc = snprintf(buf + pos, sizeof(buf) - pos, "%s%s",
			      pos ? " " : "", sbi_exts[n].name);
		if (rc < 0 || (size_t)rc >= sizeof(buf) - pos)
			break;
		pos += rc;
	}
	IMSG("SBI extensions: %s", pos ? buf : "none");
}

/**
 * sbi_ext_available() - Availability of an SBI extension
 * @extid: The extension ID
 *
 * Returns the result cached by sbi_init() for the extensions it probes and
 * falls back to a live probe for any other extension ID.
 *
 * Return: true if the extension is available, false otherwise.
 */
bool sbi_ext_available(unsigned long extid)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(sbi_exts); n++)
		if (sbi_exts[n].id == extid)
			return sbi_ext_present[n];

	return sbi_probe_extension(extid);
}

/**
 * sbi_console_putchar() - Writes given character to the console device.
 * @ch: The data to be written to the console.
 */
void sbi_console_putchar(int ch)
{
	sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch);
}

/**
 * sbi_dbcn_write_byte() - Write byte to debug console
 * @ch:         Byte to be written
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_dbcn_write_byte(unsigned char ch)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, ch);
	return ret.error;
}

/**
 * sbi_hsm_hart_start() - Start target hart at OP-TEE entry in S-mode
 * @hartid:     Target hart ID
 * @start_addr: Physical address of OP-TEE entry
 * @arg:        opaque parameter, typically used as the physical
 *              address of device-tree passed via @arg->a1
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid, start_addr,
			arg);

	return ret.error;
}

/**
 * sbi_hsm_hart_get_status() - Get the current HSM state of given hart
 * @hartid:         Target hart ID
 * @status:         Pointer to store HSM state
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_get_status(uint32_t hartid, enum sbi_hsm_hart_state *status)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_GET_STATUS, hartid);

	if (ret.error)
		return ret.error;

	*status = ret.value;
	return SBI_SUCCESS;
}
