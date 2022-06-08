// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2022, Arm Limited.
 */
#include <bench.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/embedded_ts.h>
#include <kernel/ldelf_loader.h>
#include <kernel/secure_partition.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <kernel/thread_private.h>
#include <kernel/thread_spmc.h>
#include <kernel/tpm.h>
#include <kernel/ts_store.h>
#include <ldelf.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/vm.h>
#include <optee_ffa.h>
#include <stdio.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/uuid.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>
#include <zlib.h>

#define SP_MANIFEST_ATTR_READ		BIT(0)
#define SP_MANIFEST_ATTR_WRITE		BIT(1)
#define SP_MANIFEST_ATTR_EXEC		BIT(2)
#define SP_MANIFEST_ATTR_NSEC		BIT(3)

#define SP_MANIFEST_ATTR_RO		(SP_MANIFEST_ATTR_READ)
#define SP_MANIFEST_ATTR_RW		(SP_MANIFEST_ATTR_READ | \
					 SP_MANIFEST_ATTR_WRITE)
#define SP_MANIFEST_ATTR_RX		(SP_MANIFEST_ATTR_READ | \
					 SP_MANIFEST_ATTR_EXEC)
#define SP_MANIFEST_ATTR_RWX		(SP_MANIFEST_ATTR_READ  | \
					 SP_MANIFEST_ATTR_WRITE | \
					 SP_MANIFEST_ATTR_EXEC)

#define SP_PKG_HEADER_MAGIC (0x474b5053)
#define SP_PKG_HEADER_VERSION (0x1)

struct sp_pkg_header {
	uint32_t magic;
	uint32_t version;
	uint32_t pm_offset;
	uint32_t pm_size;
	uint32_t img_offset;
	uint32_t img_size;
};

struct fip_sp_head fip_sp_list = STAILQ_HEAD_INITIALIZER(fip_sp_list);

const struct ts_ops sp_ops;

/* List that holds all of the loaded SP's */
static struct sp_sessions_head open_sp_sessions =
	TAILQ_HEAD_INITIALIZER(open_sp_sessions);

static const struct embedded_ts *find_secure_partition(const TEE_UUID *uuid)
{
	const struct sp_image *sp = NULL;
	const struct fip_sp *fip_sp = NULL;

	for_each_secure_partition(sp) {
		if (!memcmp(&sp->image.uuid, uuid, sizeof(*uuid)))
			return &sp->image;
	}

	for_each_fip_sp(fip_sp) {
		if (!memcmp(&fip_sp->sp_img.image.uuid, uuid, sizeof(*uuid)))
			return &fip_sp->sp_img.image;
	}

	return NULL;
}

bool is_sp_ctx(struct ts_ctx *ctx)
{
	return ctx && (ctx->ops == &sp_ops);
}

static void set_sp_ctx_ops(struct ts_ctx *ctx)
{
	ctx->ops = &sp_ops;
}

TEE_Result sp_find_session_id(const TEE_UUID *uuid, uint32_t *session_id)
{
	struct sp_session *s = NULL;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (!memcmp(&s->ts_sess.ctx->uuid, uuid, sizeof(*uuid))) {
			if (s->state == sp_dead)
				return TEE_ERROR_TARGET_DEAD;

			*session_id  = s->endpoint_id;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

struct sp_session *sp_get_session(uint32_t session_id)
{
	struct sp_session *s = NULL;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (s->endpoint_id == session_id)
			return s;
	}

	return NULL;
}

TEE_Result sp_partition_info_get_all(struct ffa_partition_info *fpi,
				     size_t *elem_count)
{
	size_t in_count = *elem_count;
	struct sp_session *s = NULL;
	size_t count = 0;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (s->state == sp_dead)
			continue;
		if (count < in_count) {
			spmc_fill_partition_entry(fpi, s->endpoint_id, 1);
			fpi++;
		}
		count++;
	}

	*elem_count = count;
	if (count > in_count)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_SUCCESS;
}

bool sp_has_exclusive_access(struct sp_mem_map_region *mem,
			     struct user_mode_ctx *uctx)
{
	/*
	 * Check that we have access to the region if it is supposed to be
	 * mapped to the current context.
	 */
	if (uctx) {
		struct vm_region *region = NULL;

		/* Make sure that each mobj belongs to the SP */
		TAILQ_FOREACH(region, &uctx->vm_info.regions, link) {
			if (region->mobj == mem->mobj)
				break;
		}

		if (!region)
			return false;
	}

	/* Check that it is not shared with another SP */
	return !sp_mem_is_shared(mem);
}

static uint16_t new_session_id(struct sp_sessions_head *open_sessions)
{
	struct sp_session *last = NULL;
	uint16_t id = SPMC_ENDPOINT_ID + 1;

	last = TAILQ_LAST(open_sessions, sp_sessions_head);
	if (last)
		id = last->endpoint_id + 1;

	assert(id > SPMC_ENDPOINT_ID);
	return id;
}

static TEE_Result sp_create_ctx(const TEE_UUID *uuid, struct sp_session *s)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_ctx *spc = NULL;

	/* Register context */
	spc = calloc(1, sizeof(struct sp_ctx));
	if (!spc)
		return TEE_ERROR_OUT_OF_MEMORY;

	spc->open_session = s;
	s->ts_sess.ctx = &spc->ts_ctx;
	spc->ts_ctx.uuid = *uuid;

	res = vm_info_init(&spc->uctx, &spc->ts_ctx);
	if (res)
		goto err;

	set_sp_ctx_ops(&spc->ts_ctx);

	return TEE_SUCCESS;

err:
	free(spc);
	return res;
}

static TEE_Result sp_create_session(struct sp_sessions_head *open_sessions,
				    const TEE_UUID *uuid,
				    struct sp_session **sess)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = calloc(1, sizeof(struct sp_session));

	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->endpoint_id = new_session_id(open_sessions);
	if (!s->endpoint_id) {
		res = TEE_ERROR_OVERFLOW;
		goto err;
	}

	DMSG("Loading Secure Partition %pUl", (void *)uuid);
	res = sp_create_ctx(uuid, s);
	if (res)
		goto err;

	TAILQ_INSERT_TAIL(open_sessions, s, link);
	*sess = s;
	return TEE_SUCCESS;

err:
	free(s);
	return res;
}

static TEE_Result sp_init_set_registers(struct sp_ctx *ctx)
{
	struct thread_ctx_regs *sp_regs = &ctx->sp_regs;

	memset(sp_regs, 0, sizeof(*sp_regs));
	sp_regs->sp = ctx->uctx.stack_ptr;
	sp_regs->pc = ctx->uctx.entry_func;

	return TEE_SUCCESS;
}

TEE_Result sp_map_shared(struct sp_session *s,
			 struct sp_mem_receiver *receiver,
			 struct sp_mem *smem,
			 uint64_t *va)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_ctx *ctx = NULL;
	uint32_t perm = TEE_MATTR_UR;
	struct sp_mem_map_region *reg = NULL;

	ctx = to_sp_ctx(s->ts_sess.ctx);

	/* Get the permission */
	if (receiver->perm.perm & FFA_MEM_ACC_EXE)
		perm |= TEE_MATTR_UX;

	if (receiver->perm.perm & FFA_MEM_ACC_RW) {
		if (receiver->perm.perm & FFA_MEM_ACC_EXE)
			return TEE_ERROR_ACCESS_CONFLICT;

		perm |= TEE_MATTR_UW;
	}
	/*
	 * Currently we don't support passing a va. We can't guarantee that the
	 * full region will be mapped in a contiguous region. A smem->region can
	 * have multiple mobj for one share. Currently there doesn't seem to be
	 * an option to guarantee that these will be mapped in a contiguous va
	 * space.
	 */
	if (*va)
		return TEE_ERROR_NOT_SUPPORTED;

	SLIST_FOREACH(reg, &smem->regions, link) {
		res = vm_map(&ctx->uctx, va, reg->page_count * SMALL_PAGE_SIZE,
			     perm, 0, reg->mobj, reg->page_offset);

		if (res != TEE_SUCCESS) {
			EMSG("Failed to map memory region %#"PRIx32, res);
			return res;
		}
	}
	return TEE_SUCCESS;
}

TEE_Result sp_unmap_ffa_regions(struct sp_session *s, struct sp_mem *smem)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t vaddr = 0;
	size_t len = 0;
	struct sp_ctx *ctx = to_sp_ctx(s->ts_sess.ctx);
	struct sp_mem_map_region *reg = NULL;

	SLIST_FOREACH(reg, &smem->regions, link) {
		vaddr = (vaddr_t)sp_mem_get_va(&ctx->uctx, reg->page_offset,
					       reg->mobj);
		len = reg->page_count * SMALL_PAGE_SIZE;

		res = vm_unmap(&ctx->uctx, vaddr, len);
		if (res != TEE_SUCCESS)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result sp_open_session(struct sp_session **sess,
				  struct sp_sessions_head *open_sessions,
				  const TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = NULL;
	struct sp_ctx *ctx = NULL;

	if (!find_secure_partition(uuid))
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = sp_create_session(open_sessions, uuid, &s);
	if (res != TEE_SUCCESS) {
		DMSG("sp_create_session failed %#"PRIx32, res);
		return res;
	}

	ctx = to_sp_ctx(s->ts_sess.ctx);
	assert(ctx);
	if (!ctx)
		return TEE_ERROR_TARGET_DEAD;
	*sess = s;

	ts_push_current_session(&s->ts_sess);
	/* Load the SP using ldelf. */
	ldelf_load_ldelf(&ctx->uctx);
	res = ldelf_init_with_ldelf(&s->ts_sess, &ctx->uctx);

	if (res != TEE_SUCCESS) {
		EMSG("Failed. loading SP using ldelf %#"PRIx32, res);
		ts_pop_current_session();
		return TEE_ERROR_TARGET_DEAD;
	}

	/* Make the SP ready for its first run */
	s->state = sp_idle;
	s->caller_id = 0;
	sp_init_set_registers(ctx);
	ts_pop_current_session();

	return TEE_SUCCESS;
}

static TEE_Result sp_dt_get_u64(const void *fdt, int node, const char *property,
				uint64_t *value)
{
	const fdt64_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p || len != sizeof(*p))
		return TEE_ERROR_ITEM_NOT_FOUND;

	*value = fdt64_ld(p);

	return TEE_SUCCESS;
}

static TEE_Result sp_dt_get_u32(const void *fdt, int node, const char *property,
				uint32_t *value)
{
	const fdt32_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p || len != sizeof(*p))
		return TEE_ERROR_ITEM_NOT_FOUND;

	*value = fdt32_to_cpu(*p);

	return TEE_SUCCESS;
}

static TEE_Result sp_dt_get_uuid(const void *fdt, int node,
				 const char *property, TEE_UUID *uuid)
{
	uint32_t uuid_array[4] = { 0 };
	const fdt32_t *p = NULL;
	int len = 0;
	int i = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p || len != sizeof(TEE_UUID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	for (i = 0; i < 4; i++)
		uuid_array[i] = fdt32_to_cpu(p[i]);

	tee_uuid_from_octets(uuid, (uint8_t *)uuid_array);

	return TEE_SUCCESS;
}

static TEE_Result check_fdt(const void * const fdt, const TEE_UUID *uuid)
{
	const struct fdt_property *description = NULL;
	int description_name_len = 0;
	TEE_UUID fdt_uuid = { };

	if (fdt_node_check_compatible(fdt, 0, "arm,ffa-manifest-1.0")) {
		EMSG("Failed loading SP, manifest not found");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	description = fdt_get_property(fdt, 0, "description",
				       &description_name_len);
	if (description)
		DMSG("Loading SP: %s", description->data);

	if (sp_dt_get_uuid(fdt, 0, "uuid", &fdt_uuid)) {
		EMSG("Missing or invalid UUID in SP manifest");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (memcmp(uuid, &fdt_uuid, sizeof(fdt_uuid))) {
		EMSG("Failed loading SP, UUID mismatch");
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

/*
 * sp_init_info allocates and maps the sp_ffa_init_info for the SP. It will copy
 * the fdt into the allocated page(s) and return a pointer to the new location
 * of the fdt. This pointer can be used to update data inside the fdt.
 */
static TEE_Result sp_init_info(struct sp_ctx *ctx, struct thread_smc_args *args,
			       const void * const input_fdt, vaddr_t *va,
			       size_t *num_pgs, void **fdt_copy)
{
	struct sp_ffa_init_info *info = NULL;
	int nvp_count = 1;
	size_t total_size = ROUNDUP(CFG_SP_INIT_INFO_MAX_SIZE, SMALL_PAGE_SIZE);
	size_t nvp_size = sizeof(struct sp_name_value_pair) * nvp_count;
	size_t info_size = sizeof(*info) + nvp_size;
	size_t fdt_size = total_size - info_size;
	TEE_Result res = TEE_SUCCESS;
	uint32_t perm = TEE_MATTR_URW | TEE_MATTR_PRW;
	struct fobj *f = NULL;
	struct mobj *m = NULL;
	static const char fdt_name[16] = "TYPE_DT\0\0\0\0\0\0\0\0";

	*num_pgs = total_size / SMALL_PAGE_SIZE;

	f = fobj_sec_mem_alloc(*num_pgs);
	m = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);

	fobj_put(f);
	if (!m)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(&ctx->uctx, va, total_size, perm, 0, m, 0);
	mobj_put(m);
	if (res)
		return res;

	info = (struct sp_ffa_init_info *)*va;

	/* magic field is 4 bytes, we don't copy /0 byte. */
	memcpy(&info->magic, "FF-A", 4);
	info->count = nvp_count;
	args->a0 = (vaddr_t)info;

	/*
	 * Store the fdt after the boot_info and store the pointer in the
	 * first element.
	 */
	COMPILE_TIME_ASSERT(sizeof(info->nvp[0].name) == sizeof(fdt_name));
	memcpy(info->nvp[0].name, fdt_name, sizeof(fdt_name));
	info->nvp[0].value = *va + info_size;
	info->nvp[0].size = fdt_size;
	*fdt_copy = (void *)info->nvp[0].value;

	if (fdt_open_into(input_fdt, *fdt_copy, fdt_size))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result handle_fdt_dev_regions(struct sp_ctx *ctx, void *fdt)
{
	int node = 0;
	int subnode = 0;
	TEE_Result res = TEE_SUCCESS;
	const char *dt_device_match_table = {
		"arm,ffa-manifest-device-regions",
	};

	/*
	 * Device regions are optional in the SP manifest, it's not an error if
	 * we don't find any
	 */
	node = fdt_node_offset_by_compatible(fdt, 0, dt_device_match_table);
	if (node < 0)
		return TEE_SUCCESS;

	fdt_for_each_subnode(subnode, fdt, node) {
		uint64_t base_addr = 0;
		uint32_t pages_cnt = 0;
		uint32_t attributes = 0;
		struct mobj *m = NULL;
		bool is_secure = true;
		uint32_t perm = 0;
		vaddr_t va = 0;
		unsigned int idx = 0;

		/*
		 * Physical base address of a device MMIO region.
		 * Currently only physically contiguous region is supported.
		 */
		if (sp_dt_get_u64(fdt, subnode, "base-address", &base_addr)) {
			EMSG("Mandatory field is missing: base-address");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Total size of MMIO region as count of 4K pages */
		if (sp_dt_get_u32(fdt, subnode, "pages-count", &pages_cnt)) {
			EMSG("Mandatory field is missing: pages-count");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Data access, instruction access and security attributes */
		if (sp_dt_get_u32(fdt, subnode, "attributes", &attributes)) {
			EMSG("Mandatory field is missing: attributes");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Check instruction and data access permissions */
		switch (attributes & SP_MANIFEST_ATTR_RWX) {
		case SP_MANIFEST_ATTR_RO:
			perm = TEE_MATTR_UR;
			break;
		case SP_MANIFEST_ATTR_RW:
			perm = TEE_MATTR_URW;
			break;
		default:
			EMSG("Invalid memory access permissions");
			return TEE_ERROR_BAD_FORMAT;
		}

		/*
		 * The SP is a secure endpoint, security attribute can be
		 * secure or non-secure
		 */
		if (attributes & SP_MANIFEST_ATTR_NSEC)
			is_secure = false;

		/* Memory attributes must be Device-nGnRnE */
		m = sp_mem_new_mobj(pages_cnt, TEE_MATTR_MEM_TYPE_STRONGLY_O,
				    is_secure);
		if (!m)
			return TEE_ERROR_OUT_OF_MEMORY;

		res = sp_mem_add_pages(m, &idx, (paddr_t)base_addr, pages_cnt);
		if (res) {
			mobj_put(m);
			return res;
		}

		res = vm_map(&ctx->uctx, &va, pages_cnt * SMALL_PAGE_SIZE,
			     perm, 0, m, 0);
		mobj_put(m);
		if (res)
			return res;

		/*
		 * Overwrite the device region's PA in the fdt with the VA. This
		 * fdt will be passed to the SP.
		 */
		res = fdt_setprop_u64(fdt, subnode, "base-address", va);

		/*
		 * Unmap the region if the overwrite failed since the SP won't
		 * be able to access it without knowing the VA.
		 */
		if (res) {
			vm_unmap(&ctx->uctx, va, pages_cnt * SMALL_PAGE_SIZE);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result handle_fdt_mem_regions(struct sp_ctx *ctx, void *fdt)
{
	int node = 0;
	int subnode = 0;
	tee_mm_entry_t *mm = NULL;
	TEE_Result res = TEE_SUCCESS;

	/*
	 * Memory regions are optional in the SP manifest, it's not an error if
	 * we don't find any.
	 */
	node = fdt_node_offset_by_compatible(fdt, 0,
					     "arm,ffa-manifest-memory-regions");
	if (node < 0)
		return TEE_SUCCESS;

	fdt_for_each_subnode(subnode, fdt, node) {
		bool alloc_needed = false;
		uint32_t attributes = 0;
		uint64_t base_addr = 0;
		uint32_t pages_cnt = 0;
		bool is_secure = true;
		struct mobj *m = NULL;
		unsigned int idx = 0;
		uint32_t perm = 0;
		size_t size = 0;
		vaddr_t va = 0;

		mm = NULL;

		/*
		 * Base address of a memory region.
		 * If not present, we have to allocate the specified memory.
		 * If present, this field could specify a PA or VA. Currently
		 * only a PA is supported.
		 */
		if (sp_dt_get_u64(fdt, subnode, "base-address", &base_addr))
			alloc_needed = true;

		/* Size of memory region as count of 4K pages */
		if (sp_dt_get_u32(fdt, subnode, "pages-count", &pages_cnt)) {
			EMSG("Mandatory field is missing: pages-count");
			return TEE_ERROR_BAD_FORMAT;
		}

		if (MUL_OVERFLOW(pages_cnt, SMALL_PAGE_SIZE, &size))
			return TEE_ERROR_OVERFLOW;

		/*
		 * Memory region attributes:
		 * - Instruction/data access permissions
		 * - Cacheability/shareability attributes
		 * - Security attributes
		 *
		 * Cacheability/shareability attributes can be ignored for now.
		 * OP-TEE only supports a single type for normal cached memory
		 * and currently there is no use case that would require to
		 * change this.
		 */
		if (sp_dt_get_u32(fdt, subnode, "attributes", &attributes)) {
			EMSG("Mandatory field is missing: attributes");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Check instruction and data access permissions */
		switch (attributes & SP_MANIFEST_ATTR_RWX) {
		case SP_MANIFEST_ATTR_RO:
			perm = TEE_MATTR_UR;
			break;
		case SP_MANIFEST_ATTR_RW:
			perm = TEE_MATTR_URW;
			break;
		case SP_MANIFEST_ATTR_RX:
			perm = TEE_MATTR_URX;
			break;
		default:
			EMSG("Invalid memory access permissions");
			return TEE_ERROR_BAD_FORMAT;
		}

		/*
		 * The SP is a secure endpoint, security attribute can be
		 * secure or non-secure.
		 * The SPMC cannot allocate non-secure memory, i.e. if the base
		 * address is missing this attribute must be secure.
		 */
		if (attributes & SP_MANIFEST_ATTR_NSEC) {
			if (alloc_needed) {
				EMSG("Invalid memory security attribute");
				return TEE_ERROR_BAD_FORMAT;
			}
			is_secure = false;
		}

		if (alloc_needed) {
			/* Base address is missing, we have to allocate */
			mm = tee_mm_alloc(&tee_mm_sec_ddr, size);
			if (!mm)
				return TEE_ERROR_OUT_OF_MEMORY;

			base_addr = tee_mm_get_smem(mm);
		}

		m = sp_mem_new_mobj(pages_cnt, TEE_MATTR_MEM_TYPE_CACHED,
				    is_secure);
		if (!m) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err_mm_free;
		}

		res = sp_mem_add_pages(m, &idx, base_addr, pages_cnt);
		if (res) {
			mobj_put(m);
			goto err_mm_free;
		}

		res = vm_map(&ctx->uctx, &va, size, perm, 0, m, 0);
		mobj_put(m);
		if (res)
			goto err_mm_free;

		/*
		 * Overwrite the memory region's base address in the fdt with
		 * the VA. This fdt will be passed to the SP.
		 * If the base-address field was not present in the original
		 * fdt, this function will create it. This doesn't cause issues
		 * since the necessary extra space has been allocated when
		 * opening the fdt.
		 */
		res = fdt_setprop_u64(fdt, subnode, "base-address", va);

		/*
		 * Unmap the region if the overwrite failed since the SP won't
		 * be able to access it without knowing the VA.
		 */
		if (res) {
			vm_unmap(&ctx->uctx, va, size);
			goto err_mm_free;
		}
	}

	return TEE_SUCCESS;

err_mm_free:
	tee_mm_free(mm);
	return res;
}

static TEE_Result handle_tpm_event_log(struct sp_ctx *ctx, void *fdt)
{
	uint32_t perm = TEE_MATTR_URW | TEE_MATTR_PRW;
	uint32_t dummy_size __maybe_unused = 0;
	TEE_Result res = TEE_SUCCESS;
	size_t page_count = 0;
	struct fobj *f = NULL;
	struct mobj *m = NULL;
	vaddr_t log_addr = 0;
	size_t log_size = 0;
	int node = 0;

	node = fdt_node_offset_by_compatible(fdt, 0, "arm,tpm_event_log");
	if (node < 0)
		return TEE_SUCCESS;

	/* Checking the existence and size of the event log properties */
	if (sp_dt_get_u64(fdt, node, "tpm_event_log_addr", &log_addr)) {
		EMSG("tpm_event_log_addr not found or has invalid size");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (sp_dt_get_u32(fdt, node, "tpm_event_log_size", &dummy_size)) {
		EMSG("tpm_event_log_size not found or has invalid size");
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Validating event log */
	res = tpm_get_event_log_size(&log_size);
	if (res)
		return res;

	if (!log_size) {
		EMSG("Empty TPM event log was provided");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Allocating memory area for the event log to share with the SP */
	page_count = ROUNDUP_DIV(log_size, SMALL_PAGE_SIZE);

	f = fobj_sec_mem_alloc(page_count);
	m = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(f);
	if (!m)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(&ctx->uctx, &log_addr, log_size, perm, 0, m, 0);
	mobj_put(m);
	if (res)
		return res;

	/* Copy event log */
	res = tpm_get_event_log((void *)log_addr, &log_size);
	if (res)
		goto err_unmap;

	/* Setting event log details in the manifest */
	res = fdt_setprop_u64(fdt, node, "tpm_event_log_addr", log_addr);
	if (res)
		goto err_unmap;

	res = fdt_setprop_u32(fdt, node, "tpm_event_log_size", log_size);
	if (res)
		goto err_unmap;

	return TEE_SUCCESS;

err_unmap:
	vm_unmap(&ctx->uctx, log_addr, log_size);

	return res;
}

static TEE_Result sp_init_uuid(const TEE_UUID *uuid, const void * const fdt)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *sess = NULL;
	struct thread_smc_args args = { };
	vaddr_t va = 0;
	size_t num_pgs = 0;
	struct sp_ctx *ctx = NULL;
	void *fdt_copy = NULL;

	res = sp_open_session(&sess,
			      &open_sp_sessions,
			      uuid);
	if (res)
		return res;

	res = check_fdt(fdt, uuid);
	if (res)
		return res;

	ctx = to_sp_ctx(sess->ts_sess.ctx);
	ts_push_current_session(&sess->ts_sess);

	res = sp_init_info(ctx, &args, fdt, &va, &num_pgs, &fdt_copy);
	if (res)
		goto out;

	res = handle_fdt_dev_regions(ctx, fdt_copy);
	if (res)
		goto out;

	res = handle_fdt_mem_regions(ctx, fdt_copy);
	if (res)
		goto out;

	if (IS_ENABLED(CFG_CORE_TPM_EVENT_LOG)) {
		res = handle_tpm_event_log(ctx, fdt_copy);
		if (res)
			goto out;
	}

	ts_pop_current_session();

	if (sp_enter(&args, sess)) {
		vm_unmap(&ctx->uctx, va, num_pgs);
		return FFA_ABORTED;
	}

	spmc_sp_msg_handler(&args, sess);

	ts_push_current_session(&sess->ts_sess);
out:
	/* Free the boot info page from the SP memory */
	vm_unmap(&ctx->uctx, va, num_pgs);
	ts_pop_current_session();

	return res;
}

TEE_Result sp_enter(struct thread_smc_args *args, struct sp_session *sp)
{
	TEE_Result res = FFA_OK;
	struct sp_ctx *ctx = to_sp_ctx(sp->ts_sess.ctx);

	ctx->sp_regs.x[0] = args->a0;
	ctx->sp_regs.x[1] = args->a1;
	ctx->sp_regs.x[2] = args->a2;
	ctx->sp_regs.x[3] = args->a3;
	ctx->sp_regs.x[4] = args->a4;
	ctx->sp_regs.x[5] = args->a5;
	ctx->sp_regs.x[6] = args->a6;
	ctx->sp_regs.x[7] = args->a7;

	res = sp->ts_sess.ctx->ops->enter_invoke_cmd(&sp->ts_sess, 0);

	args->a0 = ctx->sp_regs.x[0];
	args->a1 = ctx->sp_regs.x[1];
	args->a2 = ctx->sp_regs.x[2];
	args->a3 = ctx->sp_regs.x[3];
	args->a4 = ctx->sp_regs.x[4];
	args->a5 = ctx->sp_regs.x[5];
	args->a6 = ctx->sp_regs.x[6];
	args->a7 = ctx->sp_regs.x[7];

	return res;
}

static TEE_Result sp_enter_invoke_cmd(struct ts_session *s,
				      uint32_t cmd __unused)
{
	struct sp_ctx *ctx = to_sp_ctx(s->ctx);
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;
	uint64_t cpsr = 0;
	struct sp_session *sp_s = to_sp_session(s);
	struct ts_session *sess = NULL;
	struct thread_ctx_regs *sp_regs = NULL;
	uint32_t panicked = false;
	uint32_t panic_code = 0;

	bm_timestamp();

	sp_regs = &ctx->sp_regs;
	ts_push_current_session(s);

	cpsr = sp_regs->cpsr;
	sp_regs->cpsr = read_daif() & (SPSR_64_DAIF_MASK << SPSR_64_DAIF_SHIFT);

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	__thread_enter_user_mode(sp_regs, &panicked, &panic_code);
	sp_regs->cpsr = cpsr;
	thread_unmask_exceptions(exceptions);

	thread_user_clear_vfp(&ctx->uctx);

	if (panicked) {
		DMSG("SP panicked with code  %#"PRIx32, panic_code);
		abort_print_current_ts();

		sess = ts_pop_current_session();
		cpu_spin_lock(&sp_s->spinlock);
		sp_s->state = sp_dead;
		cpu_spin_unlock(&sp_s->spinlock);

		return TEE_ERROR_TARGET_DEAD;
	}

	sess = ts_pop_current_session();
	assert(sess == s);

	bm_timestamp();

	return res;
}

/* We currently don't support 32 bits */
#ifdef ARM64
static void sp_svc_store_registers(struct thread_svc_regs *regs,
				   struct thread_ctx_regs *sp_regs)
{
	COMPILE_TIME_ASSERT(sizeof(sp_regs->x[0]) == sizeof(regs->x0));
	memcpy(sp_regs->x, &regs->x0, 31 * sizeof(regs->x0));
	sp_regs->pc = regs->elr;
	sp_regs->sp = regs->sp_el0;
}
#endif

static bool sp_handle_svc(struct thread_svc_regs *regs)
{
	struct ts_session *ts = ts_get_current_session();
	struct sp_ctx *uctx = to_sp_ctx(ts->ctx);
	struct sp_session *s = uctx->open_session;

	assert(s);

	sp_svc_store_registers(regs, &uctx->sp_regs);

	regs->x0 = 0;
	regs->x1 = 0; /* panic */
	regs->x2 = 0; /* panic code */

	/*
	 * All the registers of the SP are saved in the SP session by the SVC
	 * handler.
	 * We always return to S-El1 after handling the SVC. We will continue
	 * in sp_enter_invoke_cmd() (return from __thread_enter_user_mode).
	 * The sp_enter() function copies the FF-A parameters (a0-a7) from the
	 * saved registers to the thread_smc_args. The thread_smc_args object is
	 * afterward used by the spmc_sp_msg_handler() to handle the
	 * FF-A message send by the SP.
	 */
	return false;
}

static void sp_dump_state(struct ts_ctx *ctx)
{
	struct sp_ctx *utc = to_sp_ctx(ctx);

	if (utc->uctx.dump_entry_func) {
		TEE_Result res = ldelf_dump_state(&utc->uctx);

		if (!res || res == TEE_ERROR_TARGET_DEAD)
			return;
	}

	user_mode_ctx_print_mappings(&utc->uctx);
}

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct ts_ops sp_ops __weak __relrodata_unpaged("sp_ops") = {
	.enter_invoke_cmd = sp_enter_invoke_cmd,
	.handle_svc = sp_handle_svc,
	.dump_state = sp_dump_state,
};

static TEE_Result process_sp_pkg(uint64_t sp_pkg_pa, TEE_UUID *sp_uuid)
{
	enum teecore_memtypes mtype = MEM_AREA_RAM_SEC;
	struct sp_pkg_header *sp_pkg_hdr = NULL;
	TEE_Result res = TEE_SUCCESS;
	tee_mm_entry_t *mm = NULL;
	struct fip_sp *sp = NULL;
	uint64_t sp_fdt_end = 0;
	size_t sp_pkg_size = 0;
	vaddr_t sp_pkg_va = 0;
	size_t num_pages = 0;

	/* Map only the first page of the SP package to parse the header */
	if (!tee_pbuf_is_sec(sp_pkg_pa, SMALL_PAGE_SIZE))
		return TEE_ERROR_GENERIC;

	mm = tee_mm_alloc(&tee_mm_sec_ddr, SMALL_PAGE_SIZE);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	sp_pkg_va = tee_mm_get_smem(mm);

	if (core_mmu_map_contiguous_pages(sp_pkg_va, sp_pkg_pa, 1, mtype)) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	sp_pkg_hdr = (struct sp_pkg_header *)sp_pkg_va;

	if (sp_pkg_hdr->magic != SP_PKG_HEADER_MAGIC) {
		EMSG("Invalid SP package magic");
		res = TEE_ERROR_BAD_FORMAT;
		goto err_unmap;
	}

	if (sp_pkg_hdr->version != SP_PKG_HEADER_VERSION) {
		EMSG("Invalid SP header version");
		res = TEE_ERROR_BAD_FORMAT;
		goto err_unmap;
	}

	if (ADD_OVERFLOW(sp_pkg_hdr->img_offset, sp_pkg_hdr->img_size,
			 &sp_pkg_size)) {
		EMSG("Invalid SP package size");
		res = TEE_ERROR_BAD_FORMAT;
		goto err_unmap;
	}

	if (ADD_OVERFLOW(sp_pkg_hdr->pm_offset, sp_pkg_hdr->pm_size,
			 &sp_fdt_end) || sp_fdt_end > sp_pkg_hdr->img_offset) {
		EMSG("Invalid SP manifest size");
		res = TEE_ERROR_BAD_FORMAT;
		goto err_unmap;
	}

	core_mmu_unmap_pages(sp_pkg_va, 1);
	tee_mm_free(mm);

	/* Map the whole package */
	if (!tee_pbuf_is_sec(sp_pkg_pa, sp_pkg_size))
		return TEE_ERROR_GENERIC;

	num_pages = ROUNDUP_DIV(sp_pkg_size, SMALL_PAGE_SIZE);

	mm = tee_mm_alloc(&tee_mm_sec_ddr, sp_pkg_size);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	sp_pkg_va = tee_mm_get_smem(mm);

	if (core_mmu_map_contiguous_pages(sp_pkg_va, sp_pkg_pa, num_pages,
					  mtype)) {
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	sp_pkg_hdr = (struct sp_pkg_header *)tee_mm_get_smem(mm);

	sp = calloc(1, sizeof(struct fip_sp));
	if (!sp) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_unmap;
	}

	memcpy(&sp->sp_img.image.uuid, sp_uuid, sizeof(*sp_uuid));
	sp->sp_img.image.ts = (uint8_t *)(sp_pkg_va + sp_pkg_hdr->img_offset);
	sp->sp_img.image.size = sp_pkg_hdr->img_size;
	sp->sp_img.image.flags = 0;
	sp->sp_img.fdt = (uint8_t *)(sp_pkg_va + sp_pkg_hdr->pm_offset);
	sp->mm = mm;

	STAILQ_INSERT_TAIL(&fip_sp_list, sp, link);

	return TEE_SUCCESS;

err_unmap:
	core_mmu_unmap_pages(tee_mm_get_smem(mm),
			     ROUNDUP_DIV(tee_mm_get_bytes(mm),
					 SMALL_PAGE_SIZE));
err:
	tee_mm_free(mm);

	return res;
}

static TEE_Result fip_sp_map_all(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t sp_pkg_addr = 0;
	const void *fdt = NULL;
	TEE_UUID sp_uuid = { };
	int sp_pkgs_node = 0;
	int subnode = 0;
	int root = 0;

	fdt = get_external_dt();
	if (!fdt) {
		EMSG("No SPMC manifest found");
		return TEE_ERROR_GENERIC;
	}

	root = fdt_path_offset(fdt, "/");
	if (root < 0)
		return TEE_ERROR_BAD_FORMAT;

	if (fdt_node_check_compatible(fdt, root, "arm,ffa-core-manifest-1.0"))
		return TEE_ERROR_BAD_FORMAT;

	/* SP packages are optional, it's not an error if we don't find any */
	sp_pkgs_node = fdt_node_offset_by_compatible(fdt, root, "arm,sp_pkg");
	if (sp_pkgs_node < 0)
		return TEE_SUCCESS;

	fdt_for_each_subnode(subnode, fdt, sp_pkgs_node) {
		res = sp_dt_get_u64(fdt, subnode, "load-address", &sp_pkg_addr);
		if (res) {
			EMSG("Invalid FIP SP load address");
			return res;
		}

		res = sp_dt_get_uuid(fdt, subnode, "uuid", &sp_uuid);
		if (res) {
			EMSG("Invalid FIP SP uuid");
			return res;
		}

		res = process_sp_pkg(sp_pkg_addr, &sp_uuid);
		if (res) {
			EMSG("Invalid FIP SP package");
			return res;
		}
	}

	return TEE_SUCCESS;
}

static void fip_sp_unmap_all(void)
{
	while (!STAILQ_EMPTY(&fip_sp_list)) {
		struct fip_sp *sp = STAILQ_FIRST(&fip_sp_list);

		STAILQ_REMOVE_HEAD(&fip_sp_list, link);
		core_mmu_unmap_pages(tee_mm_get_smem(sp->mm),
				     ROUNDUP_DIV(tee_mm_get_bytes(sp->mm),
						 SMALL_PAGE_SIZE));
		tee_mm_free(sp->mm);
		free(sp);
	}
}

static TEE_Result sp_init_all(void)
{
	TEE_Result res = TEE_SUCCESS;
	const struct sp_image *sp = NULL;
	const struct fip_sp *fip_sp = NULL;
	char __maybe_unused msg[60] = { '\0', };

	for_each_secure_partition(sp) {
		if (sp->image.uncompressed_size)
			snprintf(msg, sizeof(msg),
				 " (compressed, uncompressed %u)",
				 sp->image.uncompressed_size);
		else
			msg[0] = '\0';
		DMSG("SP %pUl size %u%s", (void *)&sp->image.uuid,
		     sp->image.size, msg);

		res = sp_init_uuid(&sp->image.uuid, sp->fdt);

		if (res != TEE_SUCCESS) {
			EMSG("Failed initializing SP(%pUl) err:%#"PRIx32,
			     &sp->image.uuid, res);
			if (!IS_ENABLED(CFG_SP_SKIP_FAILED))
				panic();
		}
	}

	res = fip_sp_map_all();
	if (res)
		panic("Failed mapping FIP SPs");

	for_each_fip_sp(fip_sp) {
		sp = &fip_sp->sp_img;

		DMSG("SP %pUl size %u", (void *)&sp->image.uuid,
		     sp->image.size);

		res = sp_init_uuid(&sp->image.uuid, sp->fdt);

		if (res != TEE_SUCCESS) {
			EMSG("Failed initializing SP(%pUl) err:%#"PRIx32,
			     &sp->image.uuid, res);
			if (!IS_ENABLED(CFG_SP_SKIP_FAILED))
				panic();
		}
	}

	/*
	 * At this point all FIP SPs are loaded by ldelf so the original images
	 * (loaded by BL2 earlier) can be unmapped
	 */
	fip_sp_unmap_all();

	return TEE_SUCCESS;
}

boot_final(sp_init_all);

static TEE_Result secure_partition_open(const TEE_UUID *uuid,
					struct ts_store_handle **h)
{
	return emb_ts_open(uuid, h, find_secure_partition);
}

REGISTER_SP_STORE(2) = {
	.description = "SP store",
	.open = secure_partition_open,
	.get_size = emb_ts_get_size,
	.get_tag = emb_ts_get_tag,
	.read = emb_ts_read,
	.close = emb_ts_close,
};
