/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_VIDEO_H
#define PAS_VIDEO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#include "pas_data.h"
#include "platform_pas.h"

/*
 * A Qualcomm video firmware image describes its seed with its last hashed
 * program header (newer images follow it with the hash segment): an image
 * segment of at most one page that the image fills with a placeholder. The
 * secure side fills it with random data after the image is loaded and
 * before the core starts. An image without hashed segments has no seed.
 *
 * The seed belongs to one image of one subsystem and is kept in its
 * struct qcom_pas_data: pas_video_find_seed() sets it from that image's
 * metadata and pas_video_fill_seed() consumes it, so a later start never
 * uses the location of an earlier image.
 */

/*
 * pas_video_find_seed() : locate the seed from the image metadata.
 *
 * @data:     subsystem data; its seed is set, or left invalid on error
 * @metadata: image metadata, starting with the ELF header; not authenticated
 * @e_info:   @metadata parsed by pas_elf_parse()
 *
 * Returns TEE_ERROR_BAD_FORMAT for a seed larger than a page.
 */
TEE_Result pas_video_find_seed(struct qcom_pas_data *data,
			       const uint8_t *metadata,
			       const struct elf_info *e_info);

/*
 * pas_video_fill_seed() : fill the seed of the loaded image with random data
 * and clean it to memory, where the core reads it.
 *
 * @data: subsystem data holding the firmware region of the loaded image and
 *        the seed pas_video_find_seed() set; the seed is invalid on return
 *
 * The seed is written through an existing mapping of the firmware region
 * when there is one, otherwise through a mapping added for the fill and
 * removed before returning; if removing it fails, so does the call. Returns
 * TEE_ERROR_BAD_STATE without a valid seed and TEE_ERROR_SECURITY when the
 * seed is not inside the firmware region in non-secure memory.
 */
TEE_Result pas_video_fill_seed(struct qcom_pas_data *data);

/* pas_video_clear_seed() : drop the seed of an image that will not start */
static inline void pas_video_clear_seed(struct qcom_pas_data *data)
{
	data->seed = (struct pas_video_seed){ };
}

#endif /* PAS_VIDEO_H */
