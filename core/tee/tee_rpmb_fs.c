/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <kernel/tee_common.h>
#include <tee/tee_rpmb_fs.h>
#include <tee/tee_rpmb.h>
#include <mm/tee_mm.h>
#include <stdlib.h>
#include <string.h>

#define RPMB_STORAGE_START_ADDRESS      0
#define RPMB_FS_FAT_START_ADDRESS       512
#define RPMB_STORAGE_END_ADDRESS        ((1024 * 128) - 1)
#define RPMB_BLOCK_SIZE_SHIFT           8

#define DEV_ID                          0
#define RPMB_FS_MAGIC                   0x52504D42
#define FS_VERSION                      1
#define N_ENTRIES                       16

#define FILE_IS_ACTIVE                  (1u << 0)
#define FILE_IS_LAST_ENTRY              (1u << 1)

/**
 * FS parameters: Information often used by internal functions.
 * fat_start_address will be set by rpmb_fs_setup().
 * rpmb_fs_parameters can be read by any other function.
 */
struct rpmb_fs_parameters {
	uint32_t fat_start_address;
};

/**
 * File entry for a single file in a RPMB_FS partition.
 */
struct rpmb_fat_entry {
	uint32_t start_address;
	uint32_t data_size;
	uint32_t flags;
	uint32_t write_counter;
	char filename[FILENAME_LENGTH];
};

/**
 * FAT entry context with reference to a FAT entry and its
 * location in RPMB.
 */
struct file_handle {
	/* Pointer to a fat_entry */
	struct rpmb_fat_entry fat_entry;
	/* Pointer to a filename */
	const char *filename;
	/* Adress for current entry in RPMB */
	uint32_t rpmb_fat_address;
};

/**
 * RPMB_FS partition data
 */
struct rpmb_fs_partition {
	uint32_t rpmb_fs_magic;
	uint32_t fs_version;
	uint32_t write_counter;
	uint32_t fat_start_address;
	/* Do not use reserved[] for other purpose than partition data. */
	uint8_t reserved[112];
};

static struct rpmb_fs_parameters *fs_par;

static struct file_handle *alloc_file_handle(const char *filename)
{
	struct file_handle *fh = NULL;

	fh = calloc(1, sizeof(struct file_handle));
	if (fh == NULL)
		return NULL;

	if (filename != NULL)
		fh->filename = filename;

	return fh;
}

/**
 * write_fat_entry: Store info in a fat_entry to RPMB.
 */
static TEE_Result write_fat_entry(struct file_handle *fh,
				  bool update_write_counter)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Protect partition data. */
	if (fh->rpmb_fat_address < sizeof(struct rpmb_fs_partition)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto out;
	}

	if (fh->rpmb_fat_address % sizeof(struct rpmb_fat_entry) != 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (update_write_counter) {
		res = tee_rpmb_get_write_counter(DEV_ID,
						 &fh->fat_entry.write_counter);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = tee_rpmb_write(DEV_ID, fh->rpmb_fat_address,
			     (uint8_t *)&fh->fat_entry,
			     sizeof(struct rpmb_fat_entry));

out:
	return res;
}

/**
 * rpmb_fs_setup: Setup rpmb fs.
 * Set initial partition and FS values and write to RPMB.
 * Store frequently used data in RAM.
 */
static TEE_Result rpmb_fs_setup(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fs_partition *partition_data = NULL;
	struct file_handle *fh = NULL;

	partition_data = calloc(1, sizeof(struct rpmb_fs_partition));
	if (partition_data == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_rpmb_read(DEV_ID, RPMB_STORAGE_START_ADDRESS,
			    (uint8_t *)partition_data,
			    sizeof(struct rpmb_fs_partition));
	if (res != TEE_SUCCESS)
		goto out;

	if (partition_data->rpmb_fs_magic == RPMB_FS_MAGIC) {
		if (partition_data->fs_version == FS_VERSION) {
			res = TEE_SUCCESS;
			goto store_fs_par;
		} else {
			/* Wrong software is in use. */
			res = TEE_ERROR_ACCESS_DENIED;
			goto out;
		}
	}

	/* Setup new partition data. */
	partition_data->rpmb_fs_magic = RPMB_FS_MAGIC;
	partition_data->fs_version = FS_VERSION;
	partition_data->fat_start_address = RPMB_FS_FAT_START_ADDRESS;

	/* Initial FAT entry with FILE_IS_LAST_ENTRY flag set. */
	fh = alloc_file_handle(NULL);
	if (fh == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	fh->fat_entry.flags = FILE_IS_LAST_ENTRY;
	fh->rpmb_fat_address = partition_data->fat_start_address;

	/* Write init FAT entry and partition data to RPMB. */
	res = write_fat_entry(fh, true);
	if (res != TEE_SUCCESS)
		goto out;

	res =
	    tee_rpmb_get_write_counter(DEV_ID, &partition_data->write_counter);
	if (res != TEE_SUCCESS)
		goto out;
	res = tee_rpmb_write(DEV_ID, RPMB_STORAGE_START_ADDRESS,
			     (uint8_t *)partition_data,
			     sizeof(struct rpmb_fs_partition));

store_fs_par:
	/* Store FAT start address. */
	if (fs_par == NULL) {
		fs_par = calloc(1, sizeof(struct rpmb_fs_parameters));
		if (fs_par == NULL) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	fs_par->fat_start_address = partition_data->fat_start_address;

out:
	free(fh);
	free(partition_data);

	return res;
}

/**
 * get_fat_start_address:
 * FAT start_address from fs_par.
 */
static TEE_Result get_fat_start_address(uint32_t *addr)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fs_par == NULL) {
		res = rpmb_fs_setup();
		if (res != TEE_SUCCESS)
			goto out;
	}

	*addr = fs_par->fat_start_address;
	res = TEE_SUCCESS;

out:
	return res;
}

/**
 * read_fat: Read FAT entries
 * Return matching FAT entry for read, rm rename and stat.
 * Build up memory pool and return matching entry for write operation.
 * "Last FAT entry" can be returned during write.
 */
static TEE_Result read_fat(struct file_handle *fh, tee_mm_pool_t *p)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tee_mm_entry_t *mm = NULL;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	size_t size;
	int i;
	bool entry_found = false;
	bool last_entry_found = false;

	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (fat_entries == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	while (!last_entry_found && !entry_found) {
		res = tee_rpmb_read(DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {
			/*
			 * Look for an entry, matching filenames. (read, rm,
			 * rename and stat.). Only store first filename match.
			 */
			if ((fh->filename != NULL) &&
			    (strcmp(fh->filename,
				    fat_entries[i].filename) == 0) &&
			    (fat_entries[i].flags & FILE_IS_ACTIVE) &&
			    (!entry_found)) {
				entry_found = true;
				fh->rpmb_fat_address = fat_address;
				memcpy(&fh->fat_entry, &fat_entries[i],
				       sizeof(struct rpmb_fat_entry));
				if (p == NULL)
					break;
			}

			/* Add existing files to memory pool. (write) */
			if (p != NULL) {
				if ((fat_entries[i].flags & FILE_IS_ACTIVE) !=
				    0) {
					mm = tee_mm_alloc2
						(p,
						 fat_entries[i].start_address,
						 fat_entries[i].data_size);
					if (mm == NULL) {
						res = TEE_ERROR_OUT_OF_MEMORY;
						goto out;
					}
				}

				/* Unused FAT entries can be reused (write) */
				if (((fat_entries[i].flags & FILE_IS_ACTIVE) ==
				     0) && (fh->rpmb_fat_address == 0)) {
					fh->rpmb_fat_address = fat_address;
					memcpy(&fh->fat_entry, &fat_entries[i],
					       sizeof(struct rpmb_fat_entry));
				}
			}

			if ((fat_entries[i].flags & FILE_IS_LAST_ENTRY) != 0) {
				last_entry_found = true;
				if (p != NULL && fh->rpmb_fat_address == 0) {
					fh->rpmb_fat_address = fat_address;
					fh->fat_entry.flags =
					    FILE_IS_LAST_ENTRY;
				}
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

	if ((p != NULL) && last_entry_found) {
		/* Make room for yet a FAT entry and add to memory pool. */
		fat_address += 2 * sizeof(struct rpmb_fat_entry);
		mm = tee_mm_alloc2(p, RPMB_STORAGE_START_ADDRESS, fat_address);
		if (mm == NULL) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	if (fh->filename != NULL && fh->rpmb_fat_address == 0)
		res = TEE_ERROR_FILE_NOT_FOUND;

out:
	free(fat_entries);
	return res;
}

/**
 * add_fat_entry:
 * Populate last FAT entry.
 */
static TEE_Result add_fat_entry(struct file_handle *fh)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	fh->rpmb_fat_address += sizeof(struct rpmb_fat_entry);
	res = write_fat_entry(fh, true);
	fh->rpmb_fat_address -= sizeof(struct rpmb_fat_entry);

	return res;
}

int tee_rpmb_fs_read(const char *filename, uint8_t *buf, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct file_handle *fh = NULL;
	int read_size = -1;

	if (filename == NULL || buf == NULL ||
	    strlen(filename) >= FILENAME_LENGTH - 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (fh == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	if (size < fh->fat_entry.data_size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = tee_rpmb_read(DEV_ID, fh->fat_entry.start_address, buf,
			    fh->fat_entry.data_size);

out:
	if (res == TEE_SUCCESS)
		read_size = fh->fat_entry.data_size;

	free(fh);

	return read_size;
}

int tee_rpmb_fs_write(const char *filename, uint8_t *buf, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct file_handle *fh = NULL;
	tee_mm_pool_t p;
	tee_mm_entry_t *mm = NULL;
	size_t length;
	uint32_t mm_flags;

	if (filename == NULL || buf == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	length = strlen(filename);
	if ((length >= FILENAME_LENGTH - 1) || (length == 0)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Create a FAT entry for the file to write. */
	fh = alloc_file_handle(filename);
	if (fh == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Upper memory allocation must be used for RPMB_FS. */
	mm_flags = TEE_MM_POOL_HI_ALLOC;
	if (!tee_mm_init
	    (&p, RPMB_STORAGE_START_ADDRESS, RPMB_STORAGE_END_ADDRESS,
	     RPMB_BLOCK_SIZE_SHIFT, mm_flags)) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, &p);
	if (res != TEE_SUCCESS)
		goto out;

	mm = tee_mm_alloc(&p, size);
	if (mm == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if ((fh->fat_entry.flags & FILE_IS_LAST_ENTRY) != 0) {
		res = add_fat_entry(fh);
		if (res != TEE_SUCCESS)
			goto out;
	}

	memset(&fh->fat_entry, 0, sizeof(struct rpmb_fat_entry));
	memcpy(fh->fat_entry.filename, filename, length);
	fh->fat_entry.data_size = size;
	fh->fat_entry.flags = FILE_IS_ACTIVE;
	fh->fat_entry.start_address = tee_mm_get_smem(mm);

	res = tee_rpmb_write(DEV_ID, fh->fat_entry.start_address, buf, size);
	if (res != TEE_SUCCESS)
		goto out;

	res = write_fat_entry(fh, true);

out:
	free(fh);
	if (mm != NULL)
		tee_mm_final(&p);

	if (res == TEE_SUCCESS)
		return size;

	return -1;
}

TEE_Result tee_rpmb_fs_rm(const char *filename)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct file_handle *fh = NULL;

	if (filename == NULL || strlen(filename) >= FILENAME_LENGTH - 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (fh == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	/* Clear this file entry. */
	memset(&fh->fat_entry, 0, sizeof(struct rpmb_fat_entry));
	res = write_fat_entry(fh, false);

out:
	free(fh);

	return res;
}

TEE_Result tee_rpmb_fs_rename(const char *old_name, const char *new_name)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct file_handle *fh_old = NULL;
	struct file_handle *fh_new = NULL;
	uint32_t old_len;
	uint32_t new_len;

	if (old_name == NULL || new_name == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	old_len = strlen(old_name);
	new_len = strlen(new_name);

	if ((old_len >= FILENAME_LENGTH - 1) ||
	    (new_len >= FILENAME_LENGTH - 1) || (new_len == 0)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh_old = alloc_file_handle(old_name);
	if (fh_old == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	fh_new = alloc_file_handle(new_name);
	if (fh_new == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh_old, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	res = read_fat(fh_new, NULL);
	if (res == TEE_SUCCESS) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memset(fh_old->fat_entry.filename, 0, FILENAME_LENGTH);
	memcpy(fh_old->fat_entry.filename, new_name, new_len);

	res = write_fat_entry(fh_old, false);

out:
	free(fh_old);
	free(fh_new);

	return res;
}

TEE_Result tee_rpmb_fs_stat(const char *filename,
			    struct tee_rpmb_fs_stat *stat)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct file_handle *fh = NULL;

	if (stat == NULL || filename == NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (fh == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	stat->size = fh->fat_entry.data_size;
	stat->reserved = 0;

out:
	free(fh);
	return res;
}
