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
#include <kernel/handle.h>
#include <tee/tee_rpmb_fs.h>
#include <tee/tee_rpmb.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_key_manager.h>
#include <mm/tee_mm.h>
#include <trace.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <util.h>
#include <sys/queue.h>

#ifdef CFG_ENC_FS
#include <tee/tee_cryp_provider.h>
#endif

#define RPMB_STORAGE_START_ADDRESS      0
#define RPMB_FS_FAT_START_ADDRESS       512
#define RPMB_BLOCK_SIZE_SHIFT           8

#define RPMB_FS_MAGIC                   0x52504D42
#define FS_VERSION                      2
#define N_ENTRIES                       8

#define FILE_IS_ACTIVE                  (1u << 0)
#define FILE_IS_LAST_ENTRY              (1u << 1)

/**
 * FS parameters: Information often used by internal functions.
 * fat_start_address will be set by rpmb_fs_setup().
 * rpmb_fs_parameters can be read by any other function.
 */
struct rpmb_fs_parameters {
	uint32_t fat_start_address;
	uint32_t max_rpmb_address;
};

/**
 * File entry for a single file in a RPMB_FS partition.
 */
struct rpmb_fat_entry {
	uint32_t start_address;
	uint32_t data_size;
	uint32_t flags;
	uint32_t write_counter;
	uint8_t fek[TEE_FS_KM_FEK_SIZE];
	uint8_t nonce[14];
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
};

/**
 * FAT entry context with reference to a FAT entry and its
 * location in RPMB.
 */
struct rpmb_file_handle {
	/* Pointer to a fat_entry */
	struct rpmb_fat_entry fat_entry;
	/* Pointer to a filename */
	char filename[TEE_RPMB_FS_FILENAME_LENGTH];
	/* Adress for current entry in RPMB */
	uint32_t rpmb_fat_address;
	/* Current position */
	uint32_t pos;
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

/**
 * A node in a list of directory entries. entry->name is a
 * pointer to name here.
 */
struct tee_rpmb_fs_dirent {
	struct tee_fs_dirent entry;
	char name[TEE_RPMB_FS_FILENAME_LENGTH];
	SIMPLEQ_ENTRY(tee_rpmb_fs_dirent) link;
};

/**
 * The RPMB directory representation. It contains a queue of
 * RPMB directory entries: 'next'.
 * The current pointer points to the last directory entry
 * returned by readdir().
 */
struct tee_fs_dir {
	struct tee_rpmb_fs_dirent *current;
	SIMPLEQ_HEAD(next_head, tee_rpmb_fs_dirent) next;
};

static TEE_Result get_fat_start_address(uint32_t *addr);

static struct rpmb_fs_parameters *fs_par;

static struct handle_db fs_handle_db = HANDLE_DB_INITIALIZER;

static void dump_fat(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	size_t size;
	int i;
	bool last_entry_found = false;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	while (!last_entry_found) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {

			FMSG("flags 0x%x, size %d, address 0x%x, filename '%s'",
				fat_entries[i].flags,
				fat_entries[i].data_size,
				fat_entries[i].start_address,
				fat_entries[i].filename);

			if ((fat_entries[i].flags & FILE_IS_LAST_ENTRY) != 0) {
				last_entry_found = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

out:
	free(fat_entries);
}

#if (TRACE_LEVEL >= TRACE_DEBUG)
static void dump_fh(struct rpmb_file_handle *fh)
{
	DMSG("fh->filename=%s", fh->filename);
	DMSG("fh->pos=%u", fh->pos);
	DMSG("fh->rpmb_fat_address=%u", fh->rpmb_fat_address);
	DMSG("fh->fat_entry.start_address=%u", fh->fat_entry.start_address);
	DMSG("fh->fat_entry.data_size=%u", fh->fat_entry.data_size);
}
#else
static void dump_fh(struct rpmb_file_handle *fh __unused)
{
}
#endif

static struct rpmb_file_handle *alloc_file_handle(const char *filename)
{
	struct rpmb_file_handle *fh = NULL;

	fh = calloc(1, sizeof(struct rpmb_file_handle));
	if (!fh)
		return NULL;

	if (filename)
		strlcpy(fh->filename, filename, sizeof(fh->filename));

	return fh;
}

/**
 * write_fat_entry: Store info in a fat_entry to RPMB.
 */
static TEE_Result write_fat_entry(struct rpmb_file_handle *fh,
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
		res = tee_rpmb_get_write_counter(CFG_RPMB_FS_DEV_ID,
						 &fh->fat_entry.write_counter);
		if (res != TEE_SUCCESS)
			goto out;
	}

	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, fh->rpmb_fat_address,
			     (uint8_t *)&fh->fat_entry,
			     sizeof(struct rpmb_fat_entry), NULL, NULL);

	dump_fat();

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
	struct rpmb_file_handle *fh = NULL;
	uint32_t max_rpmb_block = 0;

	if (fs_par) {
		res = TEE_SUCCESS;
		goto out;
	}

	res = tee_rpmb_get_max_block(CFG_RPMB_FS_DEV_ID, &max_rpmb_block);
	if (res != TEE_SUCCESS)
		goto out;

	partition_data = calloc(1, sizeof(struct rpmb_fs_partition));
	if (!partition_data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			    (uint8_t *)partition_data,
			    sizeof(struct rpmb_fs_partition), NULL, NULL);
	if (res != TEE_SUCCESS)
		goto out;

#ifndef CFG_RPMB_RESET_FAT
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
#else
	EMSG("**** Clearing Storage ****");
#endif

	/* Setup new partition data. */
	partition_data->rpmb_fs_magic = RPMB_FS_MAGIC;
	partition_data->fs_version = FS_VERSION;
	partition_data->fat_start_address = RPMB_FS_FAT_START_ADDRESS;

	/* Initial FAT entry with FILE_IS_LAST_ENTRY flag set. */
	fh = alloc_file_handle(NULL);
	if (!fh) {
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
	    tee_rpmb_get_write_counter(CFG_RPMB_FS_DEV_ID,
				       &partition_data->write_counter);
	if (res != TEE_SUCCESS)
		goto out;
	res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, RPMB_STORAGE_START_ADDRESS,
			     (uint8_t *)partition_data,
			     sizeof(struct rpmb_fs_partition), NULL, NULL);

#ifndef CFG_RPMB_RESET_FAT
store_fs_par:
#endif

	/* Store FAT start address. */
	fs_par = calloc(1, sizeof(struct rpmb_fs_parameters));
	if (!fs_par) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	fs_par->fat_start_address = partition_data->fat_start_address;
	fs_par->max_rpmb_address = max_rpmb_block << RPMB_BLOCK_SIZE_SHIFT;

	dump_fat();

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
	if (!fs_par)
		return TEE_ERROR_NO_DATA;

	*addr = fs_par->fat_start_address;

	return TEE_SUCCESS;
}

/**
 * read_fat: Read FAT entries
 * Return matching FAT entry for read, rm rename and stat.
 * Build up memory pool and return matching entry for write operation.
 * "Last FAT entry" can be returned during write.
 */
static TEE_Result read_fat(struct rpmb_file_handle *fh, tee_mm_pool_t *p)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tee_mm_entry_t *mm = NULL;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	size_t size;
	int i;
	bool entry_found = false;
	bool last_entry_found = false;
	bool expand_fat = false;
	struct rpmb_file_handle last_fh;

	DMSG("fat_address %d", fh->rpmb_fat_address);

	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * The pool is used to represent the current RPMB layout. To find
	 * a slot for the file tee_mm_alloc is called on the pool. Thus
	 * if it is not NULL the entire FAT must be traversed to fill in
	 * the pool.
	 */
	while (!last_entry_found && (!entry_found || p)) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {
			/*
			 * Look for an entry, matching filenames. (read, rm,
			 * rename and stat.). Only store first filename match.
			 */
			if (fh->filename &&
			    (strcmp(fh->filename,
				    fat_entries[i].filename) == 0) &&
			    (fat_entries[i].flags & FILE_IS_ACTIVE) &&
			    (!entry_found)) {
				entry_found = true;
				fh->rpmb_fat_address = fat_address;
				memcpy(&fh->fat_entry, &fat_entries[i],
				       sizeof(struct rpmb_fat_entry));
				if (!p)
					break;
			}

			/* Add existing files to memory pool. (write) */
			if (p) {
				if ((fat_entries[i].flags & FILE_IS_ACTIVE) &&
				    (fat_entries[i].data_size > 0)) {

					mm = tee_mm_alloc2
						(p,
						 fat_entries[i].start_address,
						 fat_entries[i].data_size);
					if (!mm) {
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

				/*
				 * If the last entry was reached and was chosen
				 * by the previous check, then the FAT needs to
				 * be expanded.
				 * fh->rpmb_fat_address is the address chosen
				 * to store the files FAT entry and fat_address
				 * is the current FAT entry address being
				 * compared.
				 */
				if (p && fh->rpmb_fat_address == fat_address)
					expand_fat = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

	/*
	 * Represent the FAT table in the pool.
	 */
	if (p) {
		/*
		 * Since fat_address is the start of the last entry it needs to
		 * be moved up by an entry.
		 */
		fat_address += sizeof(struct rpmb_fat_entry);

		/* Make room for yet a FAT entry and add to memory pool. */
		if (expand_fat)
			fat_address += sizeof(struct rpmb_fat_entry);

		mm = tee_mm_alloc2(p, RPMB_STORAGE_START_ADDRESS, fat_address);
		if (!mm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (expand_fat) {
			/*
			 * Point fat_address to the beginning of the new
			 * entry.
			 */
			fat_address -= sizeof(struct rpmb_fat_entry);
			memset(&last_fh, 0, sizeof(last_fh));
			last_fh.fat_entry.flags = FILE_IS_LAST_ENTRY;
			last_fh.rpmb_fat_address = fat_address;
			res = write_fat_entry(&last_fh, true);
			if (res != TEE_SUCCESS)
				goto out;
		}
	}

	if (fh->filename && !fh->rpmb_fat_address)
		res = TEE_ERROR_FILE_NOT_FOUND;

out:
	free(fat_entries);
	return res;
}

#ifdef CFG_ENC_FS
static TEE_Result generate_fek_and_nonce(struct rpmb_fat_entry *fe)
{
	TEE_Result res;

	res = crypto_ops.prng.read(fe->fek, sizeof(fe->fek));
	if (res != TEE_SUCCESS)
		return res;

	res = crypto_ops.prng.read(fe->nonce, sizeof(fe->nonce));
	return res;
}
#else
static TEE_Result generate_fek_and_nonce(struct rpmb_fat_entry *fe __unused)
{
	return TEE_SUCCESS;
}
#endif

int tee_rpmb_fs_open(const char *file, int flags, ...)
{
	int fd = -1;
	struct rpmb_file_handle *fh = NULL;
	size_t filelen;
	tee_mm_pool_t p;
	bool pool_result;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!file) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	filelen = strlen(file);
	if (filelen >= TEE_RPMB_FS_FILENAME_LENGTH - 1 || filelen == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (file[filelen - 1] == '/') {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(file);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* We need to do setup in order to make sure fs_par is filled in */
	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	if (flags & TEE_FS_O_CREATE) {
		/* Upper memory allocation must be used for RPMB_FS. */
		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  fs_par->max_rpmb_address,
					  RPMB_BLOCK_SIZE_SHIFT,
					  TEE_MM_POOL_HI_ALLOC);

		if (!pool_result) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		res = read_fat(fh, &p);
		tee_mm_final(&p);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		res = read_fat(fh, NULL);
		if (res != TEE_SUCCESS)
			goto out;
	}

	/* Add the handle to the db */
	fd = handle_get(&fs_handle_db, fh);
	if (fd == -1) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * If this is opened with create and the entry found was not active
	 * then this is a new file and the FAT entry must be written
	 */
	if (flags & TEE_FS_O_CREATE) {
		if ((fh->fat_entry.flags & FILE_IS_ACTIVE) == 0) {
			memset(&fh->fat_entry, 0,
				sizeof(struct rpmb_fat_entry));
			memcpy(fh->fat_entry.filename, file, strlen(file));
			/* Start address and size are 0 */
			fh->fat_entry.flags = FILE_IS_ACTIVE;

			res = generate_fek_and_nonce(&fh->fat_entry);
			if (res != TEE_SUCCESS) {
				handle_put(&fs_handle_db, fd);
				fd = -1;
				goto out;
			}
			DMSG("GENERATE FEK key: %p nonce: %p",
			     (void *)fh->fat_entry.fek,
			     (void *)fh->fat_entry.nonce);
			DHEXDUMP(fh->fat_entry.fek, sizeof(fh->fat_entry.fek));
			DHEXDUMP(fh->fat_entry.nonce, sizeof(fh->fat_entry.nonce));

			res = write_fat_entry(fh, true);
			if (res != TEE_SUCCESS) {
				handle_put(&fs_handle_db, fd);
				fd = -1;
				goto out;
			}
		}
	}

	res = TEE_SUCCESS;

out:
	if (res != TEE_SUCCESS) {
		if (fh)
			free(fh);

		fd = -1;
	}

	return fd;
}

int tee_rpmb_fs_close(int fd)
{
	struct rpmb_file_handle *fh;

	fh = handle_put(&fs_handle_db, fd);
	if (fh) {
		free(fh);
		return 0;
	}

	return -1;
}

int tee_rpmb_fs_read(int fd, uint8_t *buf, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh;
	int read_size = -1;

	if (!size)
		return 0;

	if (!buf) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	dump_fh(fh);

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	size = MIN(size, fh->fat_entry.data_size - fh->pos);
	if (size > 0) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
				    fh->fat_entry.start_address + fh->pos, buf,
				    size, fh->fat_entry.fek,
				    fh->fat_entry.nonce);
		if (res != TEE_SUCCESS)
			goto out;
	}

	read_size = size;
	res = TEE_SUCCESS;

out:
	if (res != TEE_SUCCESS)
		read_size = -1;

	return read_size;
}

int tee_rpmb_fs_write(int fd, uint8_t *buf, size_t size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh;
	tee_mm_pool_t p;
	bool pool_result = false;
	tee_mm_entry_t *mm;
	size_t newsize;
	uint8_t *newbuf = NULL;
	uintptr_t newaddr;

	if (!size)
		return 0;

	if (!buf) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (!fs_par) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	dump_fh(fh);

	/* Upper memory allocation must be used for RPMB_FS. */
	pool_result = tee_mm_init(&p,
				  RPMB_STORAGE_START_ADDRESS,
				  fs_par->max_rpmb_address,
				  RPMB_BLOCK_SIZE_SHIFT,
				  TEE_MM_POOL_HI_ALLOC);
	if (!pool_result) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, &p);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_ASSERT(!(fh->fat_entry.flags & FILE_IS_LAST_ENTRY));

	newsize = fh->pos + size;
	if (newsize <= fh->fat_entry.data_size) {
		/* Modifying file content */

		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID,
				     fh->fat_entry.start_address + fh->pos,
				     buf, size, fh->fat_entry.fek,
				     fh->fat_entry.nonce);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		/* Extend file: allocate, read, update, write */

		mm = tee_mm_alloc(&p, newsize);
		newbuf = calloc(newsize, 1);
		if (!mm || !newbuf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (fh->fat_entry.data_size) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address,
					    newbuf, fh->fat_entry.data_size,
					    fh->fat_entry.fek,
					    fh->fat_entry.nonce);
			if (res != TEE_SUCCESS)
				goto out;
		}

		memcpy(newbuf + fh->pos, buf, size);

		newaddr = tee_mm_get_smem(mm);
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, newaddr, newbuf,
				     newsize, fh->fat_entry.fek,
				     fh->fat_entry.nonce);
		if (res != TEE_SUCCESS)
			goto out;

		fh->fat_entry.data_size = newsize;
		fh->fat_entry.start_address = newaddr;
		res = write_fat_entry(fh, true);
		if (res != TEE_SUCCESS)
			goto out;
	}

	fh->pos = newsize;
out:
	if (pool_result)
		tee_mm_final(&p);
	if (newbuf)
		free(newbuf);

	if (res == TEE_SUCCESS)
		return size;

	return -1;
}

tee_fs_off_t tee_rpmb_fs_lseek(int fd, tee_fs_off_t offset, int whence)
{
	struct rpmb_file_handle *fh;
	TEE_Result res;
	tee_fs_off_t ret = -1;
	tee_fs_off_t new_pos;

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		return -1;

	switch (whence) {
	case TEE_FS_SEEK_SET:
		new_pos = offset;
		break;

	case TEE_FS_SEEK_CUR:
		new_pos = fh->pos + offset;
		break;

	case TEE_FS_SEEK_END:
		new_pos = fh->fat_entry.data_size + offset;
		break;

	default:
		goto exit;
	}

	if (new_pos < 0)
		new_pos = 0;

	if (new_pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		goto exit;
	}

	ret = fh->pos = new_pos;
exit:
	return ret;
}

TEE_Result tee_rpmb_fs_rm(const char *filename)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh = NULL;

	if (!filename || strlen(filename) >= TEE_RPMB_FS_FILENAME_LENGTH - 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (!fh) {
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
	IMSG("Deleting file %s returned 0x%x\n", filename, res);
	return res;
}

TEE_Result tee_rpmb_fs_rename(const char *old_name, const char *new_name)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh_old = NULL;
	struct rpmb_file_handle *fh_new = NULL;
	uint32_t old_len;
	uint32_t new_len;

	if (!old_name || !new_name) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	old_len = strlen(old_name);
	new_len = strlen(new_name);

	if ((old_len >= TEE_RPMB_FS_FILENAME_LENGTH - 1) ||
	    (new_len >= TEE_RPMB_FS_FILENAME_LENGTH - 1) || (new_len == 0)) {

		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh_old = alloc_file_handle(old_name);
	if (!fh_old) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	fh_new = alloc_file_handle(new_name);
	if (!fh_new) {
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

	memset(fh_old->fat_entry.filename, 0, TEE_RPMB_FS_FILENAME_LENGTH);
	memcpy(fh_old->fat_entry.filename, new_name, new_len);

	res = write_fat_entry(fh_old, false);

out:
	free(fh_old);
	free(fh_new);

	return res;
}

int tee_rpmb_fs_mkdir(const char *path __unused, tee_fs_mode_t mode __unused)
{
	/*
	 * FIXME: mkdir() should really create some entry in the FAT so that
	 * access() would return success when the directory exists but is
	 * empty. This does not matter for the current use cases.
	 */
	return 0;
}

int tee_rpmb_fs_ftruncate(int fd, tee_fs_off_t length)
{
	struct rpmb_file_handle *fh;
	tee_mm_pool_t p;
	bool pool_result = false;
	tee_mm_entry_t *mm;
	uint32_t newsize;
	uint8_t *newbuf = NULL;
	uintptr_t newaddr;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (length < 0 || length > INT32_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	newsize = length;

	fh = handle_lookup(&fs_handle_db, fd);
	if (!fh) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	if (newsize > fh->fat_entry.data_size) {
		/* Extend file */

		pool_result = tee_mm_init(&p,
					  RPMB_STORAGE_START_ADDRESS,
					  fs_par->max_rpmb_address,
					  RPMB_BLOCK_SIZE_SHIFT,
					  TEE_MM_POOL_HI_ALLOC);
		if (!pool_result) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		res = read_fat(fh, &p);
		if (res != TEE_SUCCESS)
			goto out;

		mm = tee_mm_alloc(&p, newsize);
		newbuf = calloc(newsize, 1);
		if (!mm || !newbuf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (fh->fat_entry.data_size) {
			res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID,
					    fh->fat_entry.start_address,
					    newbuf, fh->fat_entry.data_size,
					    fh->fat_entry.fek,
					    fh->fat_entry.nonce);
			if (res != TEE_SUCCESS)
				goto out;
		}

		newaddr = tee_mm_get_smem(mm);
		res = tee_rpmb_write(CFG_RPMB_FS_DEV_ID, newaddr, newbuf,
				     newsize, fh->fat_entry.fek,
				     fh->fat_entry.nonce);
		if (res != TEE_SUCCESS)
			goto out;

	} else {
		/* Don't change file location */
		newaddr = fh->fat_entry.start_address;
	}

	/* fh->pos is unchanged */
	fh->fat_entry.data_size = newsize;
	fh->fat_entry.start_address = newaddr;
	res = write_fat_entry(fh, true);

out:
	if (pool_result)
		tee_mm_final(&p);
	if (newbuf)
		free(newbuf);

	if (res == TEE_SUCCESS)
		return 0;

	return -1;
}

static void tee_rpmb_fs_dir_free(tee_fs_dir *dir)
{
	struct tee_rpmb_fs_dirent *e;

	if (!dir)
		return;

	free(dir->current);

	while ((e = SIMPLEQ_FIRST(&dir->next))) {
		SIMPLEQ_REMOVE_HEAD(&dir->next, link);
		free(e);
	}
}

static TEE_Result tee_rpmb_fs_dir_populate(const char *path, tee_fs_dir *dir)
{
	struct tee_rpmb_fs_dirent *current = NULL;
	struct rpmb_fat_entry *fat_entries = NULL;
	uint32_t fat_address;
	uint32_t filelen;
	char *filename;
	int i;
	bool last_entry_found = false;
	bool matched;
	struct tee_rpmb_fs_dirent *next = NULL;
	uint32_t pathlen;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t size;
	char temp;

	res = rpmb_fs_setup();
	if (res != TEE_SUCCESS)
		goto out;

	res = get_fat_start_address(&fat_address);
	if (res != TEE_SUCCESS)
		goto out;

	size = N_ENTRIES * sizeof(struct rpmb_fat_entry);
	fat_entries = malloc(size);
	if (!fat_entries) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	pathlen = strlen(path);
	while (!last_entry_found) {
		res = tee_rpmb_read(CFG_RPMB_FS_DEV_ID, fat_address,
				    (uint8_t *)fat_entries, size, NULL, NULL);
		if (res != TEE_SUCCESS)
			goto out;

		for (i = 0; i < N_ENTRIES; i++) {
			filename = fat_entries[i].filename;
			if (fat_entries[i].flags & FILE_IS_ACTIVE) {
				matched = false;
				filelen = strlen(filename);
				if (filelen > pathlen) {
					temp = filename[pathlen];
					filename[pathlen] = '\0';
					if (strcmp(filename, path) == 0)
						matched = true;

					filename[pathlen] = temp;
				}

				if (matched) {
					next = malloc(sizeof(*next));
					if (!next) {
						res = TEE_ERROR_OUT_OF_MEMORY;
						goto out;
					}

					memset(next, 0, sizeof(*next));
					next->entry.d_name = next->name;
					memcpy(next->name,
						&filename[pathlen],
						filelen - pathlen);

					SIMPLEQ_INSERT_TAIL(&dir->next, next,
							    link);
					current = next;
				}
			}

			if (fat_entries[i].flags & FILE_IS_LAST_ENTRY) {
				last_entry_found = true;
				break;
			}

			/* Move to next fat_entry. */
			fat_address += sizeof(struct rpmb_fat_entry);
		}
	}

	/* No directories were found. */
	if (!current) {
		res = TEE_ERROR_NO_DATA;
		goto out;
	}

	res = TEE_SUCCESS;

out:
	if (res != TEE_SUCCESS)
		tee_rpmb_fs_dir_free(dir);
	if (fat_entries)
		free(fat_entries);

	return res;
}

static TEE_Result tee_rpmb_fs_opendir_internal(const char *path,
						tee_fs_dir **dir)
{
	uint32_t len;
	uint32_t max_size;
	char path_local[TEE_RPMB_FS_FILENAME_LENGTH];
	TEE_Result res = TEE_ERROR_GENERIC;
	tee_fs_dir *rpmb_dir = NULL;

	if (!path || !dir) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * There must be room for at least the NULL char and a char for the
	 * filename after the path.
	 */
	max_size = TEE_RPMB_FS_FILENAME_LENGTH - 2;
	len = strlen(path);
	if (len > max_size || len == 0) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	memset(path_local, 0, sizeof(path_local));
	memcpy(path_local, path, len);

	/* Add a slash to correctly match the full directory name. */
	if (path_local[len - 1] != '/')
		path_local[len] = '/';

	rpmb_dir = calloc(1, sizeof(tee_fs_dir));
	if (!rpmb_dir) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	SIMPLEQ_INIT(&rpmb_dir->next);

	res = tee_rpmb_fs_dir_populate(path_local, rpmb_dir);
	if (res != TEE_SUCCESS) {
		free(rpmb_dir);
		rpmb_dir = NULL;
		goto out;
	}

	*dir = rpmb_dir;

out:
	return res;
}

tee_fs_dir *tee_rpmb_fs_opendir(const char *path)
{
	tee_fs_dir *dir = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tee_rpmb_fs_opendir_internal(path, &dir);
	if (res != TEE_SUCCESS)
		dir = NULL;

	return dir;
}


struct tee_fs_dirent *tee_rpmb_fs_readdir(tee_fs_dir *dir)
{
	if (!dir)
		return NULL;

	free(dir->current);

	dir->current = SIMPLEQ_FIRST(&dir->next);
	if (!dir->current)
		return NULL;

	SIMPLEQ_REMOVE_HEAD(&dir->next, link);

	return &dir->current->entry;
}

int tee_rpmb_fs_closedir(tee_fs_dir *dir)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!dir) {
		res = TEE_SUCCESS;
		goto out;
	}

	tee_rpmb_fs_dir_free(dir);
	free(dir);
	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS)
		return 0;

	return -1;
}

int tee_rpmb_fs_rmdir(const char *path)
{
	tee_fs_dir *dir = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	int ret = -1;

	/* Open the directory anyting other than NO_DATA is a failure */
	res = tee_rpmb_fs_opendir_internal(path, &dir);
	if (res == TEE_SUCCESS) {
		tee_rpmb_fs_closedir(dir);
		ret = -1;

	} else if (res == TEE_ERROR_NO_DATA) {
		ret = 0;

	} else {
		/* The case any other failure is returned */
		ret = -1;
	}


	return ret;
}

TEE_Result tee_rpmb_fs_stat(const char *filename,
			    struct tee_rpmb_fs_stat *stat)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rpmb_file_handle *fh = NULL;

	if (!stat || !filename) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	fh = alloc_file_handle(filename);
	if (!fh) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_fat(fh, NULL);
	if (res != TEE_SUCCESS)
		goto out;

	stat->size = (size_t)fh->fat_entry.data_size;
	stat->reserved = 0;

out:
	free(fh);
	return res;
}

int tee_rpmb_fs_access(const char *filename, int mode)
{
	struct tee_rpmb_fs_stat stat;
	TEE_Result res;

	/* Mode is currently ignored, this only checks for existence */
	(void)mode;

	res = tee_rpmb_fs_stat(filename, &stat);

	if (res == TEE_SUCCESS)
		return 0;

	return -1;
}

