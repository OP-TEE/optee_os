// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */

#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <ctype.h>
#include <kernel/cache_helpers.h>
#include <kernel/dt.h>
#include <kernel/hart.h>
#include <kernel/misc_arch.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <riscv.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#ifdef RV64
#define ISA_BASE_STR	"rv64"
#else
#define ISA_BASE_STR	"rv32"
#endif

/*
 * Names as they appear in "riscv,isa-extensions" and in the deprecated
 * "riscv,isa" string, single-letter extensions first.
 */
static const struct {
	const char *name;
	uint8_t ext;
} isa_ext_names[] = {
	{ "i", RISCV_ISA_EXT_I },
	{ "m", RISCV_ISA_EXT_M },
	{ "a", RISCV_ISA_EXT_A },
	{ "f", RISCV_ISA_EXT_F },
	{ "d", RISCV_ISA_EXT_D },
	{ "c", RISCV_ISA_EXT_C },
	{ "h", RISCV_ISA_EXT_H },
	{ "v", RISCV_ISA_EXT_V },
	{ "zicbom", RISCV_ISA_EXT_ZICBOM },
	{ "zicbop", RISCV_ISA_EXT_ZICBOP },
	{ "zicboz", RISCV_ISA_EXT_ZICBOZ },
	{ "zicntr", RISCV_ISA_EXT_ZICNTR },
	{ "zicsr", RISCV_ISA_EXT_ZICSR },
	{ "zifencei", RISCV_ISA_EXT_ZIFENCEI },
	{ "zihintpause", RISCV_ISA_EXT_ZIHINTPAUSE },
	{ "zihpm", RISCV_ISA_EXT_ZIHPM },
	{ "zawrs", RISCV_ISA_EXT_ZAWRS },
	{ "zba", RISCV_ISA_EXT_ZBA },
	{ "zbb", RISCV_ISA_EXT_ZBB },
	{ "zbc", RISCV_ISA_EXT_ZBC },
	{ "zbs", RISCV_ISA_EXT_ZBS },
	{ "zbkb", RISCV_ISA_EXT_ZBKB },
	{ "zbkc", RISCV_ISA_EXT_ZBKC },
	{ "zbkx", RISCV_ISA_EXT_ZBKX },
	{ "zknd", RISCV_ISA_EXT_ZKND },
	{ "zkne", RISCV_ISA_EXT_ZKNE },
	{ "zknh", RISCV_ISA_EXT_ZKNH },
	{ "zkr", RISCV_ISA_EXT_ZKR },
	{ "zksed", RISCV_ISA_EXT_ZKSED },
	{ "zksh", RISCV_ISA_EXT_ZKSH },
	{ "zkt", RISCV_ISA_EXT_ZKT },
	{ "zvbb", RISCV_ISA_EXT_ZVBB },
	{ "zvbc", RISCV_ISA_EXT_ZVBC },
	{ "zvkb", RISCV_ISA_EXT_ZVKB },
	{ "zvkg", RISCV_ISA_EXT_ZVKG },
	{ "zvkned", RISCV_ISA_EXT_ZVKNED },
	{ "zvknha", RISCV_ISA_EXT_ZVKNHA },
	{ "zvknhb", RISCV_ISA_EXT_ZVKNHB },
	{ "zvksed", RISCV_ISA_EXT_ZVKSED },
	{ "zvksh", RISCV_ISA_EXT_ZVKSH },
	{ "zvkt", RISCV_ISA_EXT_ZVKT },
	{ "zicfilp", RISCV_ISA_EXT_ZICFILP },
	{ "zicfiss", RISCV_ISA_EXT_ZICFISS },
	{ "ssdbltrp", RISCV_ISA_EXT_SSDBLTRP },
	{ "sstc", RISCV_ISA_EXT_SSTC },
	{ "svadu", RISCV_ISA_EXT_SVADU },
	{ "svinval", RISCV_ISA_EXT_SVINVAL },
	{ "svnapot", RISCV_ISA_EXT_SVNAPOT },
	{ "svpbmt", RISCV_ISA_EXT_SVPBMT },
};

/* Bit n set when extension n is available on every hart of the TEE */
static bitstr_t bit_decl(isa_common, RISCV_ISA_EXT_COUNT) __nex_bss;
/* Set once every hart of the TEE has described its ISA */
static bool __nex_bss isa_known;

/*
 * Cache block sizes of the Zicbom and Zicboz operations: the smallest one
 * over the harts of the TEE, 0 when a hart does not give it.
 */
static struct cache_block {
	unsigned int size;
	bool missing;
} cbom_block __nex_bss, cboz_block __nex_bss;

static const char *isa_ext_name(enum riscv_isa_ext ext)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(isa_ext_names); n++)
		if (isa_ext_names[n].ext == ext)
			return isa_ext_names[n].name;

	return "?";
}

static void isa_set(bitstr_t *map, const char *name, size_t len)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(isa_ext_names); n++) {
		if (strlen(isa_ext_names[n].name) == len &&
		    !strncmp(isa_ext_names[n].name, name, len)) {
			bit_set(map, isa_ext_names[n].ext);
			return;
		}
	}
}

static void isa_set_letter(bitstr_t *map, char c)
{
	switch (c) {
	case 'g':
		/* Shorthand for imafd_zicsr_zifencei */
		bit_set(map, RISCV_ISA_EXT_I);
		bit_set(map, RISCV_ISA_EXT_M);
		bit_set(map, RISCV_ISA_EXT_A);
		bit_set(map, RISCV_ISA_EXT_F);
		bit_set(map, RISCV_ISA_EXT_D);
		bit_set(map, RISCV_ISA_EXT_ZICSR);
		bit_set(map, RISCV_ISA_EXT_ZIFENCEI);
		break;
	case 'b':
		/* Shorthand for zba_zbb_zbs */
		bit_set(map, RISCV_ISA_EXT_ZBA);
		bit_set(map, RISCV_ISA_EXT_ZBB);
		bit_set(map, RISCV_ISA_EXT_ZBS);
		break;
	default:
		isa_set(map, &c, 1);
		break;
	}
}

/* Skip a "<major>p<minor>" or "<major>" version suffix, if any */
static const char *skip_version(const char *p)
{
	if (!isdigit((unsigned char)*p))
		return p;

	while (isdigit((unsigned char)*p))
		p++;

	if (*p == 'p' && isdigit((unsigned char)p[1])) {
		p++;
		while (isdigit((unsigned char)*p))
			p++;
	}

	return p;
}

/* Length of @name once a trailing "<major>p<minor>" or "<major>" is removed */
static size_t strip_version(const char *name, size_t len)
{
	size_t n = len;
	size_t m = 0;

	while (n && isdigit((unsigned char)name[n - 1]))
		n--;

	if (n < len && n && name[n - 1] == 'p') {
		m = n - 1;
		while (m && isdigit((unsigned char)name[m - 1]))
			m--;
		if (m < n - 1)
			n = m;
	}

	return n;
}

/* "riscv,isa-base" and "riscv,isa-extensions", the current binding */
static bool parse_isa_extensions(const void *fdt, int node, bitstr_t *map)
{
	const char *s = NULL;
	int count = 0;
	int len = 0;
	int n = 0;

	s = fdt_getprop(fdt, node, "riscv,isa-base", &len);
	if (!s)
		return false;

	if (strcmp(s, ISA_BASE_STR "i")) {
		EMSG("Core built for %s, device tree describes \"%s\"",
		     ISA_BASE_STR, s);
		panic();
	}
	bit_set(map, RISCV_ISA_EXT_I);

	count = fdt_stringlist_count(fdt, node, "riscv,isa-extensions");
	for (n = 0; n < count; n++) {
		s = fdt_stringlist_get(fdt, node, "riscv,isa-extensions", n,
				       &len);
		if (s && len > 0)
			isa_set(map, s, len);
	}

	return true;
}

/*
 * The deprecated "riscv,isa" string, "rv64imafdc_zicsr_zifencei" and
 * the like: single-letter extensions first, then "_"-separated names,
 * each optionally followed by a version.
 */
static bool parse_isa_string(const void *fdt, int node, bitstr_t *map)
{
	const char *p = NULL;
	const char *e = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, "riscv,isa", &len);
	if (!p)
		return false;

	if (strncmp(p, ISA_BASE_STR, strlen(ISA_BASE_STR))) {
		EMSG("Core built for %s, device tree describes \"%s\"",
		     ISA_BASE_STR, p);
		panic();
	}
	p += strlen(ISA_BASE_STR);

	while (*p && *p != '_') {
		/*
		 * Old device trees end the single-letter part with "su"
		 * for the privilege modes, which are not extensions.
		 */
		if (*p != 's' && *p != 'u')
			isa_set_letter(map, *p);
		p++;
		p = skip_version(p);
	}

	while (*p == '_') {
		p++;
		e = p;
		while (*e && *e != '_')
			e++;
		isa_set(map, p, strip_version(p, e - p));
		p = e;
	}

	return true;
}

static bool is_tee_hart(uint32_t hartid)
{
	size_t n = 0;

	for (n = 0; n < hartids_count; n++)
		if (hartids[n] == hartid)
			return true;

	return false;
}

static void read_cache_block(const void *fdt, int node, const char *prop,
			     struct cache_block *blk)
{
	uint32_t size = 0;

	if (fdt_read_uint32(fdt, node, prop, &size) || !size) {
		blk->missing = true;
		return;
	}

	if (!blk->size || size < blk->size)
		blk->size = size;
}

static unsigned int cache_block_size(const struct cache_block *blk)
{
	if (blk->missing)
		return 0;

	return blk->size;
}

/* Read what the CPU node of every hart of the TEE describes */
static void parse_cpu_nodes(const void *fdt)
{
	bitstr_t bit_decl(common, RISCV_ISA_EXT_COUNT) = { };
	bitstr_t bit_decl(map, RISCV_ISA_EXT_COUNT) = { };
	const char *type = NULL;
	uint32_t hartid = 0;
	bool missing = false;
	bool found = false;
	int cpus = 0;
	int node = 0;
	size_t n = 0;

	/* Start from everything and keep what each hart has */
	memset(common, 0xff, sizeof(common));

	cpus = fdt_path_offset(fdt, "/cpus");
	if (cpus < 0)
		return;

	fdt_for_each_subnode(node, fdt, cpus) {
		type = fdt_getprop(fdt, node, "device_type", NULL);
		if (!type || strcmp(type, "cpu"))
			continue;

		if (fdt_read_uint32(fdt, node, "reg", &hartid) ||
		    !is_tee_hart(hartid))
			continue;

		read_cache_block(fdt, node, "riscv,cbom-block-size",
				 &cbom_block);
		read_cache_block(fdt, node, "riscv,cboz-block-size",
				 &cboz_block);

		memset(map, 0, sizeof(map));
		if (!parse_isa_extensions(fdt, node, map) &&
		    !parse_isa_string(fdt, node, map)) {
			IMSG("hart%"PRIu32": ISA not in the device tree",
			     hartid);
			missing = true;
		}

		for (n = 0; n < sizeof(common); n++)
			common[n] &= map[n];
		found = true;
	}

	/* One hart without a description leaves the ISA unknown */
	isa_known = found && !missing;
	if (isa_known)
		memcpy(isa_common, common, sizeof(isa_common));
}

#ifdef CFG_RISCV_M_MODE
static void isa_from_misa(void)
{
	unsigned long ext = read_csr(CSR_MISA);
	unsigned int n = 0;

	for (n = 0; n < 26; n++)
		if (ext & BIT(n))
			isa_set_letter(isa_common, 'a' + n);

	isa_known = true;
}
#endif

static void print_isa(void)
{
	char buf[80] = { };
	const char *name = NULL;
	size_t pos = 0;
	size_t len = 0;
	size_t n = 0;

	if (!isa_known) {
		IMSG("ISA: not described");
		return;
	}

	pos = snprintf(buf, sizeof(buf), "ISA: %s", ISA_BASE_STR);
	for (n = 0; n < ARRAY_SIZE(isa_ext_names); n++) {
		name = isa_ext_names[n].name;
		len = strlen(name);
		if (!bit_test(isa_common, isa_ext_names[n].ext))
			continue;

		if (len > 1)
			len++;	/* "_" separator */
		if (pos + len >= sizeof(buf)) {
			IMSG("%s", buf);
			pos = snprintf(buf, sizeof(buf), "    ");
		}
		if (len > 1)
			buf[pos++] = '_';
		memcpy(buf + pos, name, strlen(name));
		pos += strlen(name);
		buf[pos] = '\0';
	}
	IMSG("%s", buf);
}

/*
 * The core is built for a fixed ISA (riscv.mk). When the device tree
 * describes the harts, make sure that ISA is available on all of them
 * instead of faulting on the first instruction that is not.
 */
static void check_build_isa(void)
{
	static const struct {
		uint8_t ext;
		bool required;
		const char *cfg;
	} reqs[] = {
		{ RISCV_ISA_EXT_M, true, "the base ISA" },
		{ RISCV_ISA_EXT_A, true, "the base ISA" },
		{ RISCV_ISA_EXT_F, IS_ENABLED(CFG_RISCV_FPU), "CFG_RISCV_FPU" },
		{ RISCV_ISA_EXT_D, IS_ENABLED(CFG_RISCV_FPU), "CFG_RISCV_FPU" },
		{ RISCV_ISA_EXT_C, IS_ENABLED(CFG_RISCV_ISA_C),
		  "CFG_RISCV_ISA_C" },
		{ RISCV_ISA_EXT_ZBB, IS_ENABLED(CFG_RISCV_ISA_ZBB),
		  "CFG_RISCV_ISA_ZBB" },
	};
	size_t n = 0;

	if (!isa_known)
		return;

	for (n = 0; n < ARRAY_SIZE(reqs); n++) {
		if (reqs[n].required && !bit_test(isa_common, reqs[n].ext)) {
			EMSG("Extension %s required by %s missing on a hart",
			     isa_ext_name(reqs[n].ext), reqs[n].cfg);
			panic();
		}
	}
}

/*
 * Generic code aligns the buffers it maintains in cache to
 * cache_get_max_line_size(). A cache block larger than that would make a
 * Zicbom operation reach into the neighbouring data.
 */
static void check_cache_block(void)
{
	unsigned int cbom = riscv_cbom_block_size();
	unsigned int cboz = riscv_cboz_block_size();

	if (cbom || cboz)
		IMSG("Cache block size: Zicbom %u, Zicboz %u", cbom, cboz);

	if (cbom > cache_get_max_line_size()) {
		EMSG("Zicbom block size %u above CFG_MAX_CACHE_LINE_SHIFT (%u)",
		     cbom, cache_get_max_line_size());
		panic();
	}
}

bool riscv_isa_ext_available(enum riscv_isa_ext ext)
{
	assert(ext < RISCV_ISA_EXT_COUNT);

	return isa_known && bit_test(isa_common, ext);
}

unsigned int riscv_cbom_block_size(void)
{
	return cache_block_size(&cbom_block);
}

unsigned int riscv_cboz_block_size(void)
{
	return cache_block_size(&cboz_block);
}

void hart_features_init(void)
{
	const void *fdt = get_external_dt();

	if (fdt) {
		parse_cpu_nodes(fdt);
	} else {
#ifdef CFG_RISCV_M_MODE
		isa_from_misa();
#endif
	}

	print_isa();
	check_build_isa();
	check_cache_block();
}
