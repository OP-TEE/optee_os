// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <drivers/qcom/cmd_db/cmd_db.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

register_phys_mem(MEM_AREA_RAM_NSEC, AOP_CMD_DB_BASE, AOP_CMD_DB_SIZE);

#define CMD_DB_MAGIC_NUM		0x0c0330db
#define CMD_DB_VER			0x00000001

#define CMD_DB_SLV_ID_ACTUAL		3
#define CMD_DB_SLV_ID_RESERVE		5
#define CMD_DB_MAX_SLV_ID		(CMD_DB_SLV_ID_ACTUAL + \
					 CMD_DB_SLV_ID_RESERVE)

#define CMD_DB_SLV_ID_VALID_LOW		3
#define CMD_DB_SLV_ID_VALID_HIGH	5

#define CMD_DB_RES_ID_MAX_CHARS		8
#define CMD_DB_CHAR_BITS		8

#define CMD_DB_GET_ENTRY_PTR(slv_info, idx) \
	(query_db.data->data + (slv_info)->header_offset + \
	 sizeof(struct entry_header) * (idx))

#define CMD_DB_GET_DATA_PTR(slv_info, offset) \
	(query_db.data->data + (slv_info)->data_offset + (offset))

struct cmd_db_query_result_type {
	char res_id[CMD_DB_MAX_RES_ID_LEN + 1];
	uint32_t addr;
	uint32_t len;
	uint16_t version;
};

struct entry_header {
	uint64_t res_id;
	uint32_t priority[CMD_DB_DRV_ID_PRIORITY_SZ];
	uint32_t addr;
	uint16_t len;
	uint16_t offset;
};

struct slv_id_info {
	uint16_t slv_id;
	uint16_t header_offset;
	uint16_t data_offset;
	uint16_t cnt;
	uint16_t version;
	uint16_t reserved[3];
};

struct db_header {
	uint32_t version;
	uint32_t magic_num;
	struct slv_id_info slv_id_info[CMD_DB_MAX_SLV_ID];
	uint32_t check_sum;
	uint32_t reserved;
	uint8_t data[];
};

struct cmd_db_data {
	struct db_header *data;
	size_t size;
	struct mutex lock; /* Protects CMD_DB data access */
};

static struct cmd_db_data query_db = {
	.lock = MUTEX_INITIALIZER,
};

static uint64_t conv_str_to_uint64(const char *res_id)
{
	uint64_t value = 0;
	size_t len = 0;
	size_t i = 0;

	len = strnlen(res_id, CMD_DB_RES_ID_MAX_CHARS + 1);
	if (len == 0 || len > CMD_DB_RES_ID_MAX_CHARS)
		return 0;

	for (i = 0; i < len; i++)
		value |= SHIFT_U64((uint64_t)res_id[i], CMD_DB_CHAR_BITS * i);

	return value;
}

static bool is_valid_res_id(const char *res_id)
{
	if (!res_id || !res_id[0])
		return false;

	return (strnlen(res_id, CMD_DB_RES_ID_MAX_CHARS + 1) <=
		CMD_DB_RES_ID_MAX_CHARS);
}

static TEE_Result cmd_db_init(void)
{
	query_db.data = phys_to_virt(AOP_CMD_DB_BASE, MEM_AREA_RAM_NSEC,
				     AOP_CMD_DB_SIZE);
	if (!query_db.data) {
		EMSG("CMD_DB: Failed to map at PA 0x%lx",
		     (unsigned long)AOP_CMD_DB_BASE);
		goto err_panic;
	}

	query_db.size = AOP_CMD_DB_SIZE;

	if (query_db.data->version != CMD_DB_VER ||
	    query_db.data->magic_num != CMD_DB_MAGIC_NUM) {
		EMSG("CMD_DB: Version/magic mismatch: 0x%"PRIx32"/0x%"PRIx32
		     " exp 0x%"PRIx32"/0x%"PRIx32,
		     query_db.data->version, query_db.data->magic_num,
		     CMD_DB_VER, CMD_DB_MAGIC_NUM);
		goto err_panic;
	}

	return TEE_SUCCESS;

err_panic:
	panic("CMD_DB driver initialization failed");
}

static TEE_Result validate_entry_bounds(struct slv_id_info *slv_info,
					uint16_t entry_idx)
{
	size_t entry_size = 0;
	size_t offset = 0;
	size_t bounds = 0;

	if (MUL_OVERFLOW(sizeof(struct entry_header), entry_idx, &entry_size) ||
	    ADD_OVERFLOW(slv_info->header_offset, entry_size, &offset) ||
	    ADD_OVERFLOW(sizeof(struct db_header), offset, &bounds) ||
	    ADD_OVERFLOW(bounds, sizeof(struct entry_header), &bounds) ||
	    bounds > query_db.size)
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

static TEE_Result search_entry(uint64_t res_id, uint16_t *slv_idx,
			       struct entry_header *entry)
{
	struct slv_id_info *slv_info = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint16_t i = 0;
	uint16_t j = 0;

	if (!query_db.data)
		return TEE_ERROR_BAD_STATE;

	if (!res_id)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < CMD_DB_MAX_SLV_ID; i++) {
		slv_info = &query_db.data->slv_id_info[i];

		if (slv_info->slv_id < CMD_DB_SLV_ID_VALID_LOW ||
		    slv_info->slv_id > CMD_DB_SLV_ID_VALID_HIGH)
			continue;

		for (j = 0; j < slv_info->cnt; j++) {
			res = validate_entry_bounds(slv_info, j);
			if (res != TEE_SUCCESS)
				return res;

			memcpy(entry, CMD_DB_GET_ENTRY_PTR(slv_info, j),
			       sizeof(*entry));

			if (res_id == entry->res_id)
				goto out_found;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;

out_found:
	*slv_idx = i;
	return TEE_SUCCESS;
}

static TEE_Result copy_aux_data(uint16_t slv_idx, struct entry_header *entry,
				struct cmd_db_query_result_type *result,
				uint8_t *data)
{
	struct slv_id_info *slv_info = &query_db.data->slv_id_info[slv_idx];
	uint32_t len = MIN(result->len, entry->len);
	size_t offset = 0;
	size_t bounds = 0;

	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(slv_info->data_offset, entry->offset, &offset) ||
	    ADD_OVERFLOW(sizeof(struct db_header), offset, &bounds) ||
	    ADD_OVERFLOW(bounds, len, &bounds) ||
	    bounds > query_db.size)
		return TEE_ERROR_CORRUPT_OBJECT;

	memcpy(data, CMD_DB_GET_DATA_PTR(slv_info, entry->offset), len);
	result->len = len;

	return TEE_SUCCESS;
}

static TEE_Result
cmd_db_get_entry_by_res_id(const char *res_id,
			   struct cmd_db_query_result_type *result,
			   uint8_t *data)
{
	struct entry_header entry = { };
	TEE_Result res = TEE_SUCCESS;
	uint64_t res_id_val = 0;
	uint16_t slv_idx = 0;

	if (!res_id || !result || (!data && result->len > 0))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!res_id[0])
		return TEE_ERROR_BAD_PARAMETERS;

	res_id_val = conv_str_to_uint64(res_id);

	res = search_entry(res_id_val, &slv_idx, &entry);
	if (res)
		return res;

	strlcpy(result->res_id, res_id, sizeof(result->res_id));
	result->addr = entry.addr;
	result->version = query_db.data->slv_id_info[slv_idx].version;

	if (entry.len == 0)
		return TEE_SUCCESS;

	if (result->len == 0) {
		result->len = entry.len;
		return TEE_SUCCESS;
	}

	return copy_aux_data(slv_idx, &entry, result, data);
}

TEE_Result cmd_db_get_addr(const char *res_id, uint32_t *addr)
{
	struct cmd_db_query_result_type result = { };
	TEE_Result res = TEE_SUCCESS;

	if (!addr || !is_valid_res_id(res_id))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&query_db.lock);

	if (!query_db.data) {
		mutex_unlock(&query_db.lock);
		return TEE_ERROR_BAD_STATE;
	}

	res = cmd_db_get_entry_by_res_id(res_id, &result, NULL);
	if (res == TEE_SUCCESS)
		*addr = result.addr;

	mutex_unlock(&query_db.lock);
	return res;
}

early_init_late(cmd_db_init);
