// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020-2024, Arm Limited.
 */
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

#define BOUNCE_BUFFER_SIZE		4096

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

#define SP_MANIFEST_FLAG_NOBITS	BIT(0)

#define SP_MANIFEST_NS_INT_QUEUED	(0x0)
#define SP_MANIFEST_NS_INT_MANAGED_EXIT	(0x1)
#define SP_MANIFEST_NS_INT_SIGNALED	(0x2)

#define SP_PKG_HEADER_MAGIC (0x474b5053)
#define SP_PKG_HEADER_VERSION_V1 (0x1)
#define SP_PKG_HEADER_VERSION_V2 (0x2)

struct sp_pkg_header {
	uint32_t magic;
	uint32_t version;
	uint32_t pm_offset;
	uint32_t pm_size;
	uint32_t img_offset;
	uint32_t img_size;
};

struct fip_sp_head fip_sp_list = STAILQ_HEAD_INITIALIZER(fip_sp_list);

static const struct ts_ops sp_ops;

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

struct sp_session *sp_get_session(uint32_t session_id)
{
	struct sp_session *s = NULL;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (s->endpoint_id == session_id)
			return s;
	}

	return NULL;
}

TEE_Result sp_partition_info_get(uint32_t ffa_vers, void *buf, size_t buf_size,
				 const TEE_UUID *ffa_uuid, size_t *elem_count,
				 bool count_only)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t part_props = FFA_PART_PROP_DIRECT_REQ_RECV |
			      FFA_PART_PROP_DIRECT_REQ_SEND;
	struct sp_session *s = NULL;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (ffa_uuid &&
		    memcmp(&s->ffa_uuid, ffa_uuid, sizeof(*ffa_uuid)))
			continue;

		if (s->state == sp_dead)
			continue;
		if (!count_only && !res) {
			uint32_t uuid_words[4] = { 0 };

			tee_uuid_to_octets((uint8_t *)uuid_words, &s->ffa_uuid);
			res = spmc_fill_partition_entry(ffa_vers, buf, buf_size,
							*elem_count,
							s->endpoint_id, 1,
							part_props, uuid_words);
		}
		*elem_count += 1;
	}

	return res;
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

static bool endpoint_id_is_valid(uint32_t id)
{
	/*
	 * These IDs are assigned at the SPMC init so already have valid values
	 * by the time this function gets first called
	 */
	return id != spmd_id && id != spmc_id && id != optee_endpoint_id &&
	       id >= FFA_SWD_ID_MIN && id <= FFA_SWD_ID_MAX;
}

static TEE_Result new_session_id(uint16_t *endpoint_id)
{
	uint32_t id = 0;

	/* Find the first available endpoint id */
	for (id = FFA_SWD_ID_MIN; id <= FFA_SWD_ID_MAX; id++) {
		if (endpoint_id_is_valid(id) && !sp_get_session(id)) {
			*endpoint_id = id;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_FORMAT;
}

static TEE_Result sp_create_ctx(const TEE_UUID *bin_uuid, struct sp_session *s)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_ctx *spc = NULL;

	/* Register context */
	spc = calloc(1, sizeof(struct sp_ctx));
	if (!spc)
		return TEE_ERROR_OUT_OF_MEMORY;

	spc->open_session = s;
	s->ts_sess.ctx = &spc->ts_ctx;
	spc->ts_ctx.uuid = *bin_uuid;

	res = vm_info_init(&spc->uctx, &spc->ts_ctx);
	if (res)
		goto err;

	set_sp_ctx_ops(&spc->ts_ctx);

	return TEE_SUCCESS;

err:
	free(spc);
	return res;
}

/*
 * Insert a new sp_session to the sessions list, so that it is ordered
 * by boot_order.
 */
static void insert_session_ordered(struct sp_sessions_head *open_sessions,
				   struct sp_session *session)
{
	struct sp_session *s = NULL;

	if (!open_sessions || !session)
		return;

	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		if (s->boot_order > session->boot_order)
			break;
	}

	if (!s)
		TAILQ_INSERT_TAIL(open_sessions, session, link);
	else
		TAILQ_INSERT_BEFORE(s, session, link);
}

static TEE_Result sp_create_session(struct sp_sessions_head *open_sessions,
				    const TEE_UUID *bin_uuid,
				    const uint32_t boot_order,
				    struct sp_session **sess)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = calloc(1, sizeof(struct sp_session));

	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->boot_order = boot_order;

	res = new_session_id(&s->endpoint_id);
	if (res)
		goto err;

	DMSG("Loading Secure Partition %pUl", (void *)bin_uuid);
	res = sp_create_ctx(bin_uuid, s);
	if (res)
		goto err;

	insert_session_ordered(open_sessions, s);
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

static TEE_Result sp_dt_get_u64(const void *fdt, int node, const char *property,
				uint64_t *value)
{
	const fdt64_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len != sizeof(*p))
		return TEE_ERROR_BAD_FORMAT;

	*value = fdt64_ld(p);

	return TEE_SUCCESS;
}

static TEE_Result sp_dt_get_u32(const void *fdt, int node, const char *property,
				uint32_t *value)
{
	const fdt32_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len != sizeof(*p))
		return TEE_ERROR_BAD_FORMAT;

	*value = fdt32_to_cpu(*p);

	return TEE_SUCCESS;
}

static TEE_Result sp_dt_get_u16(const void *fdt, int node, const char *property,
				uint16_t *value)
{
	const fdt16_t *p = NULL;
	int len = 0;

	p = fdt_getprop(fdt, node, property, &len);
	if (!p)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len != sizeof(*p))
		return TEE_ERROR_BAD_FORMAT;

	*value = fdt16_to_cpu(*p);

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
	if (!p)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len != sizeof(TEE_UUID))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < 4; i++)
		uuid_array[i] = fdt32_to_cpu(p[i]);

	tee_uuid_from_octets(uuid, (uint8_t *)uuid_array);

	return TEE_SUCCESS;
}

static TEE_Result sp_is_elf_format(const void *fdt, int sp_node,
				   bool *is_elf_format)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t elf_format = 0;

	res = sp_dt_get_u32(fdt, sp_node, "elf-format", &elf_format);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	*is_elf_format = (elf_format != 0);

	return TEE_SUCCESS;
}

static TEE_Result sp_binary_open(const TEE_UUID *uuid,
				 const struct ts_store_ops **ops,
				 struct ts_store_handle **handle)
{
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	SCATTERED_ARRAY_FOREACH(*ops, sp_stores, struct ts_store_ops) {
		res = (*ops)->open(uuid, handle);
		if (res != TEE_ERROR_ITEM_NOT_FOUND &&
		    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
			break;
	}

	return res;
}

static TEE_Result load_binary_sp(struct ts_session *s,
				 struct user_mode_ctx *uctx)
{
	size_t bin_size = 0, bin_size_rounded = 0, bin_page_count = 0;
	size_t bb_size = ROUNDUP(BOUNCE_BUFFER_SIZE, SMALL_PAGE_SIZE);
	size_t bb_num_pages = bb_size / SMALL_PAGE_SIZE;
	const struct ts_store_ops *store_ops = NULL;
	struct ts_store_handle *handle = NULL;
	TEE_Result res = TEE_SUCCESS;
	tee_mm_entry_t *mm = NULL;
	struct fobj *fobj = NULL;
	struct mobj *mobj = NULL;
	uaddr_t base_addr = 0;
	uint32_t vm_flags = 0;
	unsigned int idx = 0;
	vaddr_t va = 0;

	if (!s || !uctx)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Loading raw binary format SP %pUl", &uctx->ts_ctx->uuid);

	/* Initialize the bounce buffer */
	fobj = fobj_sec_mem_alloc(bb_num_pages);
	mobj = mobj_with_fobj_alloc(fobj, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(uctx, &va, bb_size, TEE_MATTR_PRW, 0, mobj, 0);
	mobj_put(mobj);
	if (res)
		return res;

	uctx->bbuf = (uint8_t *)va;
	uctx->bbuf_size = BOUNCE_BUFFER_SIZE;

	vm_set_ctx(uctx->ts_ctx);

	/* Find TS store and open SP binary */
	res = sp_binary_open(&uctx->ts_ctx->uuid, &store_ops, &handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open SP binary");
		return res;
	}

	/* Query binary size and calculate page count */
	res = store_ops->get_size(handle, &bin_size);
	if (res != TEE_SUCCESS)
		goto err;

	if (ROUNDUP_OVERFLOW(bin_size, SMALL_PAGE_SIZE, &bin_size_rounded)) {
		res = TEE_ERROR_OVERFLOW;
		goto err;
	}

	bin_page_count = bin_size_rounded / SMALL_PAGE_SIZE;

	/* Allocate memory */
	mm = tee_mm_alloc(&tee_mm_sec_ddr, bin_size_rounded);
	if (!mm) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	base_addr = tee_mm_get_smem(mm);

	/* Create mobj */
	mobj = sp_mem_new_mobj(bin_page_count, TEE_MATTR_MEM_TYPE_CACHED, true);
	if (!mobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_free_tee_mm;
	}

	res = sp_mem_add_pages(mobj, &idx, base_addr, bin_page_count);
	if (res)
		goto err_free_mobj;

	/* Map memory area for the SP binary */
	va = 0;
	res = vm_map(uctx, &va, bin_size_rounded, TEE_MATTR_URWX,
		     vm_flags, mobj, 0);
	if (res)
		goto err_free_mobj;

	/* Read SP binary into the previously mapped memory area */
	res = store_ops->read(handle, NULL, (void *)va, bin_size);
	if (res)
		goto err_unmap;

	/* Set memory protection to allow execution */
	res = vm_set_prot(uctx, va, bin_size_rounded, TEE_MATTR_UX);
	if (res)
		goto err_unmap;

	mobj_put(mobj);
	store_ops->close(handle);

	/* The entry point must be at the beginning of the SP binary. */
	uctx->entry_func = va;
	uctx->load_addr = va;
	uctx->is_32bit = false;

	s->handle_scall = s->ctx->ops->handle_scall;

	return TEE_SUCCESS;

err_unmap:
	vm_unmap(uctx, va, bin_size_rounded);

err_free_mobj:
	mobj_put(mobj);

err_free_tee_mm:
	tee_mm_free(mm);

err:
	store_ops->close(handle);

	return res;
}

static TEE_Result sp_open_session(struct sp_session **sess,
				  struct sp_sessions_head *open_sessions,
				  const TEE_UUID *ffa_uuid,
				  const TEE_UUID *bin_uuid,
				  const uint32_t boot_order,
				  const void *fdt)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *s = NULL;
	struct sp_ctx *ctx = NULL;
	bool is_elf_format = false;

	if (!find_secure_partition(bin_uuid))
		return TEE_ERROR_ITEM_NOT_FOUND;

	res = sp_create_session(open_sessions, bin_uuid, boot_order, &s);
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

	res = sp_is_elf_format(fdt, 0, &is_elf_format);
	if (res == TEE_SUCCESS) {
		if (is_elf_format) {
			/* Load the SP using ldelf. */
			ldelf_load_ldelf(&ctx->uctx);
			res = ldelf_init_with_ldelf(&s->ts_sess, &ctx->uctx);
		} else {
			/* Raw binary format SP */
			res = load_binary_sp(&s->ts_sess, &ctx->uctx);
		}
	} else {
		EMSG("Failed to detect SP format");
	}

	if (res != TEE_SUCCESS) {
		EMSG("Failed loading SP  %#"PRIx32, res);
		ts_pop_current_session();
		return TEE_ERROR_TARGET_DEAD;
	}

	/*
	 * Make the SP ready for its first run.
	 * Set state to busy to prevent other endpoints from sending messages to
	 * the SP before its boot phase is done.
	 */
	s->state = sp_busy;
	s->caller_id = 0;
	sp_init_set_registers(ctx);
	memcpy(&s->ffa_uuid, ffa_uuid, sizeof(*ffa_uuid));
	ts_pop_current_session();

	return TEE_SUCCESS;
}

static TEE_Result fdt_get_uuid(const void * const fdt, TEE_UUID *uuid)
{
	const struct fdt_property *description = NULL;
	int description_name_len = 0;

	if (fdt_node_check_compatible(fdt, 0, "arm,ffa-manifest-1.0")) {
		EMSG("Failed loading SP, manifest not found");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	description = fdt_get_property(fdt, 0, "description",
				       &description_name_len);
	if (description)
		DMSG("Loading SP: %s", description->data);

	if (sp_dt_get_uuid(fdt, 0, "uuid", uuid)) {
		EMSG("Missing or invalid UUID in SP manifest");
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

static TEE_Result copy_and_map_fdt(struct sp_ctx *ctx, const void * const fdt,
				   void **fdt_copy, size_t *mapped_size)
{
	size_t total_size = ROUNDUP(fdt_totalsize(fdt), SMALL_PAGE_SIZE);
	size_t num_pages = total_size / SMALL_PAGE_SIZE;
	uint32_t perm = TEE_MATTR_UR | TEE_MATTR_PRW;
	TEE_Result res = TEE_SUCCESS;
	struct mobj *m = NULL;
	struct fobj *f = NULL;
	vaddr_t va = 0;

	f = fobj_sec_mem_alloc(num_pages);
	m = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(f);
	if (!m)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(&ctx->uctx, &va, total_size, perm, 0, m, 0);
	mobj_put(m);
	if (res)
		return res;

	if (fdt_open_into(fdt, (void *)va, total_size))
		return TEE_ERROR_GENERIC;

	*fdt_copy = (void *)va;
	*mapped_size = total_size;

	return res;
}

static void fill_boot_info_1_0(vaddr_t buf, const void *fdt)
{
	struct ffa_boot_info_1_0 *info = (struct ffa_boot_info_1_0 *)buf;
	static const char fdt_name[16] = "TYPE_DT\0\0\0\0\0\0\0\0";

	memcpy(&info->magic, "FF-A", 4);
	info->count = 1;

	COMPILE_TIME_ASSERT(sizeof(info->nvp[0].name) == sizeof(fdt_name));
	memcpy(info->nvp[0].name, fdt_name, sizeof(fdt_name));
	info->nvp[0].value = (uintptr_t)fdt;
	info->nvp[0].size = fdt_totalsize(fdt);
}

static void fill_boot_info_1_1(vaddr_t buf, const void *fdt)
{
	size_t desc_offs = ROUNDUP(sizeof(struct ffa_boot_info_header_1_1), 8);
	struct ffa_boot_info_header_1_1 *header =
		(struct ffa_boot_info_header_1_1 *)buf;
	struct ffa_boot_info_1_1 *desc =
		(struct ffa_boot_info_1_1 *)(buf + desc_offs);

	header->signature = FFA_BOOT_INFO_SIGNATURE;
	header->version = FFA_BOOT_INFO_VERSION;
	header->blob_size = desc_offs + sizeof(struct ffa_boot_info_1_1);
	header->desc_size = sizeof(struct ffa_boot_info_1_1);
	header->desc_count = 1;
	header->desc_offset = desc_offs;

	memset(&desc[0].name, 0, sizeof(desc[0].name));
	/* Type: Standard boot info (bit[7] == 0), FDT type */
	desc[0].type = FFA_BOOT_INFO_TYPE_ID_FDT;
	/* Flags: Contents field contains an address */
	desc[0].flags = FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR <<
			FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT;
	desc[0].size = fdt_totalsize(fdt);
	desc[0].contents = (uintptr_t)fdt;
}

static TEE_Result create_and_map_boot_info(struct sp_ctx *ctx, const void *fdt,
					   struct thread_smc_args *args,
					   vaddr_t *va, size_t *mapped_size,
					   uint32_t sp_ffa_version)
{
	size_t total_size = ROUNDUP(CFG_SP_INIT_INFO_MAX_SIZE, SMALL_PAGE_SIZE);
	size_t num_pages = total_size / SMALL_PAGE_SIZE;
	uint32_t perm = TEE_MATTR_UR | TEE_MATTR_PRW;
	TEE_Result res = TEE_SUCCESS;
	struct fobj *f = NULL;
	struct mobj *m = NULL;
	uint32_t info_reg = 0;

	f = fobj_sec_mem_alloc(num_pages);
	m = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(f);
	if (!m)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(&ctx->uctx, va, total_size, perm, 0, m, 0);
	mobj_put(m);
	if (res)
		return res;

	*mapped_size = total_size;

	switch (sp_ffa_version) {
	case MAKE_FFA_VERSION(1, 0):
		fill_boot_info_1_0(*va, fdt);
		break;
	case MAKE_FFA_VERSION(1, 1):
		fill_boot_info_1_1(*va, fdt);
		break;
	default:
		EMSG("Unknown FF-A version: %#"PRIx32, sp_ffa_version);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = sp_dt_get_u32(fdt, 0, "gp-register-num", &info_reg);
	if (res) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND) {
			/* If the property is not present, set default to x0 */
			info_reg = 0;
		} else {
			return TEE_ERROR_BAD_FORMAT;
		}
	}

	switch (info_reg) {
	case 0:
		args->a0 = *va;
		break;
	case 1:
		args->a1 = *va;
		break;
	case 2:
		args->a2 = *va;
		break;
	case 3:
		args->a3 = *va;
		break;
	default:
		EMSG("Invalid register selected for passing boot info");
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

static TEE_Result handle_fdt_load_relative_mem_regions(struct sp_ctx *ctx,
						       const void *fdt)
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
		uint64_t load_rel_offset = 0;
		uint32_t attributes = 0;
		uint64_t base_addr = 0;
		uint32_t pages_cnt = 0;
		uint32_t flags = 0;
		uint32_t perm = 0;
		size_t size = 0;
		vaddr_t va = 0;

		mm = NULL;

		/* Load address relative offset of a memory region */
		if (!sp_dt_get_u64(fdt, subnode, "load-address-relative-offset",
				   &load_rel_offset)) {
			va = ctx->uctx.load_addr + load_rel_offset;
		} else {
			/* Skip non load address relative memory regions */
			continue;
		}

		if (!sp_dt_get_u64(fdt, subnode, "base-address", &base_addr)) {
			EMSG("Both base-address and load-address-relative-offset fields are set");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Size of memory region as count of 4K pages */
		if (sp_dt_get_u32(fdt, subnode, "pages-count", &pages_cnt)) {
			EMSG("Mandatory field is missing: pages-count");
			return TEE_ERROR_BAD_FORMAT;
		}

		if (MUL_OVERFLOW(pages_cnt, SMALL_PAGE_SIZE, &size))
			return TEE_ERROR_OVERFLOW;

		/* Memory region attributes  */
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

		res = sp_dt_get_u32(fdt, subnode, "load-flags", &flags);
		if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND) {
			EMSG("Optional field with invalid value: flags");
			return TEE_ERROR_BAD_FORMAT;
		}

		/* Load relative regions must be secure */
		if (attributes & SP_MANIFEST_ATTR_NSEC) {
			EMSG("Invalid memory security attribute");
			return TEE_ERROR_BAD_FORMAT;
		}

		if (flags & SP_MANIFEST_FLAG_NOBITS) {
			/*
			 * NOBITS flag is set, which means that loaded binary
			 * doesn't contain this area, so it's need to be
			 * allocated.
			 */
			struct mobj *m = NULL;
			unsigned int idx = 0;

			mm = tee_mm_alloc(&tee_mm_sec_ddr, size);
			if (!mm)
				return TEE_ERROR_OUT_OF_MEMORY;

			base_addr = tee_mm_get_smem(mm);

			m = sp_mem_new_mobj(pages_cnt,
					    TEE_MATTR_MEM_TYPE_CACHED, true);
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
		} else {
			/*
			 * If NOBITS is not present the memory area is already
			 * mapped and only need to set the correct permissions.
			 */
			res = vm_set_prot(&ctx->uctx, va, size, perm);
			if (res)
				return res;
		}
	}

	return TEE_SUCCESS;

err_mm_free:
	tee_mm_free(mm);
	return res;
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

static TEE_Result swap_sp_endpoints(uint32_t endpoint_id,
				    uint32_t new_endpoint_id)
{
	struct sp_session *session = sp_get_session(endpoint_id);
	uint32_t manifest_endpoint_id = 0;

	/*
	 * We don't know in which order the SPs are loaded. The endpoint ID
	 * defined in the manifest could already be generated by
	 * new_session_id() and used by another SP. If this is the case, we swap
	 * the ID's of the two SPs. We also have to make sure that the ID's are
	 * not defined twice in the manifest.
	 */

	/* The endpoint ID was not assigned yet */
	if (!session)
		return TEE_SUCCESS;

	/*
	 * Read the manifest file from the SP who originally had the endpoint.
	 * We can safely swap the endpoint ID's if the manifest file doesn't
	 * have an endpoint ID defined.
	 */
	if (!sp_dt_get_u32(session->fdt, 0, "id", &manifest_endpoint_id)) {
		assert(manifest_endpoint_id == endpoint_id);
		EMSG("SP: Found duplicated endpoint ID %#"PRIx32, endpoint_id);
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	session->endpoint_id = new_endpoint_id;

	return TEE_SUCCESS;
}

static TEE_Result read_manifest_endpoint_id(struct sp_session *s)
{
	uint32_t endpoint_id = 0;

	/*
	 * The endpoint ID can be optionally defined in the manifest file. We
	 * have to map the ID inside the manifest to the SP if it's defined.
	 * If not, the endpoint ID generated inside new_session_id() will be
	 * used.
	 */
	if (!sp_dt_get_u32(s->fdt, 0, "id", &endpoint_id)) {
		TEE_Result res = TEE_ERROR_GENERIC;

		if (!endpoint_id_is_valid(endpoint_id)) {
			EMSG("Invalid endpoint ID 0x%"PRIx32, endpoint_id);
			return TEE_ERROR_BAD_FORMAT;
		}

		res = swap_sp_endpoints(endpoint_id, s->endpoint_id);
		if (res)
			return res;

		DMSG("SP: endpoint ID (0x%"PRIx32") found in manifest",
		     endpoint_id);
		/* Assign the endpoint ID to the current SP */
		s->endpoint_id = endpoint_id;
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
		uint64_t load_rel_offset = 0;
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

		/* Load address relative offset of a memory region */
		if (!sp_dt_get_u64(fdt, subnode, "load-address-relative-offset",
				   &load_rel_offset)) {
			/*
			 * At this point the memory region is already mapped by
			 * handle_fdt_load_relative_mem_regions.
			 * Only need to set the base-address in the manifest and
			 * then skip the rest of the mapping process.
			 */
			va = ctx->uctx.load_addr + load_rel_offset;
			res = fdt_setprop_u64(fdt, subnode, "base-address", va);
			if (res)
				return res;

			continue;
		}

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

/*
 * Note: this function is called only on the primary CPU. It assumes that the
 * features present on the primary CPU are available on all of the secondary
 * CPUs as well.
 */
static TEE_Result handle_hw_features(void *fdt)
{
	uint32_t val __maybe_unused = 0;
	TEE_Result res = TEE_SUCCESS;
	int node = 0;

	/*
	 * HW feature descriptions are optional in the SP manifest, it's not an
	 * error if we don't find any.
	 */
	node = fdt_node_offset_by_compatible(fdt, 0, "arm,hw-features");
	if (node < 0)
		return TEE_SUCCESS;

	/* Modify the crc32 property only if it's already present */
	if (!sp_dt_get_u32(fdt, node, "crc32", &val)) {
		res = fdt_setprop_u32(fdt, node, "crc32",
				      feat_crc32_implemented());
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result read_ns_interrupts_action(const void *fdt,
					    struct sp_session *s)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	res = sp_dt_get_u32(fdt, 0, "ns-interrupts-action", &s->ns_int_mode);

	if (res) {
		EMSG("Mandatory property is missing: ns-interrupts-action");
		return res;
	}

	switch (s->ns_int_mode) {
	case SP_MANIFEST_NS_INT_QUEUED:
	case SP_MANIFEST_NS_INT_SIGNALED:
		/* OK */
		break;

	case SP_MANIFEST_NS_INT_MANAGED_EXIT:
		EMSG("Managed exit is not implemented");
		return TEE_ERROR_NOT_IMPLEMENTED;

	default:
		EMSG("Invalid ns-interrupts-action value: %"PRIu32,
		     s->ns_int_mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result read_ffa_version(const void *fdt, struct sp_session *s)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t ffa_version = 0;

	res = sp_dt_get_u32(fdt, 0, "ffa-version", &ffa_version);
	if (res) {
		EMSG("Mandatory property is missing: ffa-version");
		return res;
	}

	if (ffa_version != FFA_VERSION_1_0 && ffa_version != FFA_VERSION_1_1) {
		EMSG("Invalid FF-A version value: 0x%08"PRIx32, ffa_version);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	s->rxtx.ffa_vers = ffa_version;

	return TEE_SUCCESS;
}

static TEE_Result sp_init_uuid(const TEE_UUID *bin_uuid, const void * const fdt)
{
	TEE_Result res = TEE_SUCCESS;
	struct sp_session *sess = NULL;
	TEE_UUID ffa_uuid = {};
	uint16_t boot_order = 0;
	uint32_t boot_order_arg = 0;

	res = fdt_get_uuid(fdt, &ffa_uuid);
	if (res)
		return res;

	res = sp_dt_get_u16(fdt, 0, "boot-order", &boot_order);
	if (res == TEE_SUCCESS) {
		boot_order_arg = boot_order;
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		boot_order_arg = UINT32_MAX;
	} else {
		EMSG("Failed reading boot-order property err:%#"PRIx32, res);
		return res;
	}

	res = sp_open_session(&sess,
			      &open_sp_sessions,
			      &ffa_uuid, bin_uuid, boot_order_arg, fdt);
	if (res)
		return res;

	sess->fdt = fdt;

	res = read_manifest_endpoint_id(sess);
	if (res)
		return res;
	DMSG("endpoint is 0x%"PRIx16, sess->endpoint_id);

	res = read_ns_interrupts_action(fdt, sess);
	if (res)
		return res;

	res = read_ffa_version(fdt, sess);
	if (res)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result sp_first_run(struct sp_session *sess)
{
	TEE_Result res = TEE_SUCCESS;
	struct thread_smc_args args = { };
	struct sp_ctx *ctx = NULL;
	vaddr_t boot_info_va = 0;
	size_t boot_info_size = 0;
	void *fdt_copy = NULL;
	size_t fdt_size = 0;

	ctx = to_sp_ctx(sess->ts_sess.ctx);
	ts_push_current_session(&sess->ts_sess);
	sess->is_initialized = false;

	/*
	 * Load relative memory regions must be handled before doing any other
	 * mapping to prevent conflicts in the VA space.
	 */
	res = handle_fdt_load_relative_mem_regions(ctx, sess->fdt);
	if (res) {
		ts_pop_current_session();
		return res;
	}

	res = copy_and_map_fdt(ctx, sess->fdt, &fdt_copy, &fdt_size);
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

	res = handle_hw_features(fdt_copy);
	if (res)
		goto out;

	res = create_and_map_boot_info(ctx, fdt_copy, &args, &boot_info_va,
				       &boot_info_size, sess->rxtx.ffa_vers);
	if (res)
		goto out;

	ts_pop_current_session();

	res = sp_enter(&args, sess);
	if (res) {
		ts_push_current_session(&sess->ts_sess);
		goto out;
	}

	spmc_sp_msg_handler(&args, sess);

	ts_push_current_session(&sess->ts_sess);
	sess->is_initialized = true;

out:
	/* Free the boot info page from the SP memory */
	vm_unmap(&ctx->uctx, boot_info_va, boot_info_size);
	vm_unmap(&ctx->uctx, (vaddr_t)fdt_copy, fdt_size);
	ts_pop_current_session();

	return res;
}

TEE_Result sp_enter(struct thread_smc_args *args, struct sp_session *sp)
{
	TEE_Result res = TEE_SUCCESS;
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

/*
 * According to FF-A v1.1 section 8.3.1.4 if a caller requires less permissive
 * active on NS interrupt than the callee, the callee must inherit the caller's
 * configuration.
 * Each SP's own NS action setting is stored in ns_int_mode. The effective
 * action will be MIN([self action], [caller's action]) which is stored in the
 * ns_int_mode_inherited field.
 */
static void sp_cpsr_configure_foreign_interrupts(struct sp_session *s,
						 struct ts_session *caller,
						 uint64_t *cpsr)
{
	if (caller) {
		struct sp_session *caller_sp = to_sp_session(caller);

		s->ns_int_mode_inherited = MIN(caller_sp->ns_int_mode_inherited,
					       s->ns_int_mode);
	} else {
		s->ns_int_mode_inherited = s->ns_int_mode;
	}

	if (s->ns_int_mode_inherited == SP_MANIFEST_NS_INT_QUEUED)
		*cpsr |= SHIFT_U32(THREAD_EXCP_FOREIGN_INTR,
				   ARM32_CPSR_F_SHIFT);
	else
		*cpsr &= ~SHIFT_U32(THREAD_EXCP_FOREIGN_INTR,
				    ARM32_CPSR_F_SHIFT);
}

static TEE_Result sp_enter_invoke_cmd(struct ts_session *s,
				      uint32_t cmd __unused)
{
	struct sp_ctx *ctx = to_sp_ctx(s->ctx);
	TEE_Result res = TEE_SUCCESS;
	uint32_t exceptions = 0;
	struct sp_session *sp_s = to_sp_session(s);
	struct ts_session *sess = NULL;
	struct thread_ctx_regs *sp_regs = NULL;
	uint32_t thread_id = THREAD_ID_INVALID;
	struct ts_session *caller = NULL;
	uint32_t rpc_target_info = 0;
	uint32_t panicked = false;
	uint32_t panic_code = 0;

	sp_regs = &ctx->sp_regs;
	ts_push_current_session(s);

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	/* Enable/disable foreign interrupts in CPSR/SPSR */
	caller = ts_get_calling_session();
	sp_cpsr_configure_foreign_interrupts(sp_s, caller, &sp_regs->cpsr);

	/*
	 * Store endpoint ID and thread ID in rpc_target_info. This will be used
	 * as w1 in FFA_INTERRUPT in case of a foreign interrupt.
	 */
	rpc_target_info = thread_get_tsd()->rpc_target_info;
	thread_id = thread_get_id();
	assert(thread_id <= UINT16_MAX);
	thread_get_tsd()->rpc_target_info =
		FFA_TARGET_INFO_SET(sp_s->endpoint_id, thread_id);

	__thread_enter_user_mode(sp_regs, &panicked, &panic_code);

	/* Restore rpc_target_info */
	thread_get_tsd()->rpc_target_info = rpc_target_info;

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

	return res;
}

/* We currently don't support 32 bits */
#ifdef ARM64
static void sp_svc_store_registers(struct thread_scall_regs *regs,
				   struct thread_ctx_regs *sp_regs)
{
	COMPILE_TIME_ASSERT(sizeof(sp_regs->x[0]) == sizeof(regs->x0));
	memcpy(sp_regs->x, &regs->x0, 31 * sizeof(regs->x0));
	sp_regs->pc = regs->elr;
	sp_regs->sp = regs->sp_el0;
}
#endif

static bool sp_handle_scall(struct thread_scall_regs *regs)
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

static const struct ts_ops sp_ops = {
	.enter_invoke_cmd = sp_enter_invoke_cmd,
	.handle_scall = sp_handle_scall,
	.dump_state = sp_dump_state,
};

static TEE_Result process_sp_pkg(uint64_t sp_pkg_pa, TEE_UUID *sp_uuid)
{
	enum teecore_memtypes mtype = MEM_AREA_TA_RAM;
	struct sp_pkg_header *sp_pkg_hdr = NULL;
	struct fip_sp *sp = NULL;
	uint64_t sp_fdt_end = 0;
	size_t sp_pkg_size = 0;
	vaddr_t sp_pkg_va = 0;

	/* Process the first page which contains the SP package header */
	sp_pkg_va = (vaddr_t)phys_to_virt(sp_pkg_pa, mtype, SMALL_PAGE_SIZE);
	if (!sp_pkg_va) {
		EMSG("Cannot find mapping for PA %#" PRIxPA, sp_pkg_pa);
		return TEE_ERROR_GENERIC;
	}

	sp_pkg_hdr = (struct sp_pkg_header *)sp_pkg_va;

	if (sp_pkg_hdr->magic != SP_PKG_HEADER_MAGIC) {
		EMSG("Invalid SP package magic");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (sp_pkg_hdr->version != SP_PKG_HEADER_VERSION_V1 &&
	    sp_pkg_hdr->version != SP_PKG_HEADER_VERSION_V2) {
		EMSG("Invalid SP header version");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (ADD_OVERFLOW(sp_pkg_hdr->img_offset, sp_pkg_hdr->img_size,
			 &sp_pkg_size)) {
		EMSG("Invalid SP package size");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (ADD_OVERFLOW(sp_pkg_hdr->pm_offset, sp_pkg_hdr->pm_size,
			 &sp_fdt_end) || sp_fdt_end > sp_pkg_hdr->img_offset) {
		EMSG("Invalid SP manifest size");
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Process the whole SP package now that the size is known */
	sp_pkg_va = (vaddr_t)phys_to_virt(sp_pkg_pa, mtype, sp_pkg_size);
	if (!sp_pkg_va) {
		EMSG("Cannot find mapping for PA %#" PRIxPA, sp_pkg_pa);
		return TEE_ERROR_GENERIC;
	}

	sp_pkg_hdr = (struct sp_pkg_header *)sp_pkg_va;

	sp = calloc(1, sizeof(struct fip_sp));
	if (!sp)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(&sp->sp_img.image.uuid, sp_uuid, sizeof(*sp_uuid));
	sp->sp_img.image.ts = (uint8_t *)(sp_pkg_va + sp_pkg_hdr->img_offset);
	sp->sp_img.image.size = sp_pkg_hdr->img_size;
	sp->sp_img.image.flags = 0;
	sp->sp_img.fdt = (uint8_t *)(sp_pkg_va + sp_pkg_hdr->pm_offset);

	STAILQ_INSERT_TAIL(&fip_sp_list, sp, link);

	return TEE_SUCCESS;
}

static TEE_Result fip_sp_init_all(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t sp_pkg_addr = 0;
	const void *fdt = NULL;
	TEE_UUID sp_uuid = { };
	int sp_pkgs_node = 0;
	int subnode = 0;
	int root = 0;

	fdt = get_manifest_dt();
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

static void fip_sp_deinit_all(void)
{
	while (!STAILQ_EMPTY(&fip_sp_list)) {
		struct fip_sp *sp = STAILQ_FIRST(&fip_sp_list);

		STAILQ_REMOVE_HEAD(&fip_sp_list, link);
		free(sp);
	}
}

static TEE_Result sp_init_all(void)
{
	TEE_Result res = TEE_SUCCESS;
	const struct sp_image *sp = NULL;
	const struct fip_sp *fip_sp = NULL;
	char __maybe_unused msg[60] = { '\0', };
	struct sp_session *s = NULL;
	struct sp_session *prev_sp = NULL;

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

	res = fip_sp_init_all();
	if (res)
		panic("Failed initializing FIP SPs");

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
	 * At this point all FIP SPs are loaded by ldelf or by the raw binary SP
	 * loader, so the original images (loaded by BL2) are not needed anymore
	 */
	fip_sp_deinit_all();

	/*
	 * Now that all SPs are loaded, check through the boot order values,
	 * and warn in case there is a non-unique value.
	 */
	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		/* User specified boot-order values are uint16 */
		if (s->boot_order > UINT16_MAX)
			break;

		if (prev_sp && prev_sp->boot_order == s->boot_order)
			IMSG("WARNING: duplicated boot-order (%pUl vs %pUl)",
			     &prev_sp->ts_sess.ctx->uuid,
			     &s->ts_sess.ctx->uuid);

		prev_sp = s;
	}

	/* Continue the initialization and run the SP */
	TAILQ_FOREACH(s, &open_sp_sessions, link) {
		DMSG("Starting SP: 0x%"PRIx16, s->endpoint_id);

		res = sp_first_run(s);
		if (res != TEE_SUCCESS) {
			EMSG("Failed starting SP(0x%"PRIx16") err:%#"PRIx32,
			     s->endpoint_id, res);
			if (!IS_ENABLED(CFG_SP_SKIP_FAILED))
				panic();
		}
	}

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
