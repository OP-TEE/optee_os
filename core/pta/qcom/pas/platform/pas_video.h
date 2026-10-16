/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_VIDEO_H
#define PAS_VIDEO_H

#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>

#include "pas_data.h"

/*
 * struct pas_video_seed : seed segment of a video firmware image.
 *
 * A Qualcomm video firmware image describes its seed with its last program
 * header: a loadable image segment of at most one page that the image fills
 * with a placeholder. The secure side fills it with random data after the
 * image is loaded and before the core starts. An image whose last program
 * header is not an image segment has no seed.
 *
 * The seed belongs to one image: pas_video_find_seed() sets it from that
 * image's metadata and pas_video_fill_seed() consumes it, so a later start
 * never uses the location of an earlier image.
 *
 * @valid:  set by pas_video_find_seed() for the image being loaded
 * @offset: offset of the seed from the start of the firmware region
 * @size:   size of the seed, 0 when the image has none
 */
struct pas_video_seed {
	bool valid;
	size_t offset;
	size_t size;
};

/*
 * pas_video_find_seed() : locate the seed from the image metadata.
 *
 * @metadata: image metadata, starting with the ELF header; borrowed and not
 *            authenticated: it is only read, through copies, during the call
 * @size:     size of @metadata
 * @seed:     out, the seed; left invalid on error
 *
 * Returns TEE_ERROR_BAD_FORMAT for metadata that cannot be parsed or a seed
 * larger than a page or below the lowest image segment.
 */
TEE_Result pas_video_find_seed(const void *metadata, size_t size,
			       struct pas_video_seed *seed);

/*
 * pas_video_fill_seed() : fill the seed of the loaded image with random data
 * and clean it to memory, where the core reads it.
 *
 * @data: subsystem data holding the firmware region set by PAS mem_setup
 * @seed: seed returned by pas_video_find_seed(); invalid on return
 *
 * The seed is written through an existing mapping of the firmware region
 * when there is one, otherwise through a mapping added for the fill and
 * removed before returning; if removing it fails, so does the call. Returns
 * TEE_ERROR_BAD_STATE without a valid seed and TEE_ERROR_SECURITY when the
 * seed is not inside the firmware region in non-secure memory.
 */
TEE_Result pas_video_fill_seed(const struct qcom_pas_data *data,
			       struct pas_video_seed *seed);

/* pas_video_clear_seed() : drop the seed of an image that will not start */
static inline void pas_video_clear_seed(struct pas_video_seed *seed)
{
	*seed = (struct pas_video_seed){ };
}

#endif /* PAS_VIDEO_H */
