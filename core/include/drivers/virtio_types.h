/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DRIVERS_VIRTIO_TYPES_H
#define __DRIVERS_VIRTIO_TYPES_H

/* Shared local types for Virtio frontend and backend implementations. */

#include <assert.h>
#include <drivers/virtio_config.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

#define VIRTIO_FEATURE_WORDS		4U
#define VIRTIO_FEATURE_BITS		(VIRTIO_FEATURE_WORDS * 32)
/* Feature bits above 127 are not negotiated by this core. */
struct virtio_features {
	uint32_t words[VIRTIO_FEATURE_WORDS];
};

static inline bool
virtio_feature_test(const struct virtio_features *feat, unsigned int bit)
{
	assert(bit < VIRTIO_FEATURE_BITS);
	return feat->words[bit / 32] & BIT32(bit % 32);
}

static inline void virtio_feature_set(struct virtio_features *feat,
				      unsigned int bit)
{
	assert(bit < VIRTIO_FEATURE_BITS);
	feat->words[bit / 32] |= BIT32(bit % 32);
}

static inline void virtio_feature_clear(struct virtio_features *feat,
					unsigned int bit)
{
	assert(bit < VIRTIO_FEATURE_BITS);
	feat->words[bit / 32] &= ~BIT32(bit % 32);
}

static inline void virtio_features_reset(struct virtio_features *feat)
{
	*feat = (struct virtio_features){ };
}

static inline void virtio_features_or(struct virtio_features *dst,
				      const struct virtio_features *src)
{
	size_t n = 0;

	for (n = 0; n < VIRTIO_FEATURE_WORDS; n++)
		dst->words[n] |= src->words[n];
}

/* Keep only feature bits in @dst that are also set in @src. */
static inline void virtio_features_and(struct virtio_features *dst,
				       const struct virtio_features *src)
{
	size_t n = 0;

	for (n = 0; n < VIRTIO_FEATURE_WORDS; n++)
		dst->words[n] &= src->words[n];
}

/* Return true if @feat contains every bit set in @required_feat. */
static inline bool
virtio_features_include(const struct virtio_features *feat,
			const struct virtio_features *required_feat)
{
	size_t n = 0;

	for (n = 0; n < VIRTIO_FEATURE_WORDS; n++)
		if (required_feat->words[n] & ~feat->words[n])
			return false;
	return true;
}

/* Check that all set feature bits are device-specific. */
static inline bool
virtio_features_are_device_specific(const struct virtio_features *feat)
{
	static const struct virtio_features allowed = {
		.words = {
			VIRTIO_DEVICE_FEATURES_WORD0_MASK,
			VIRTIO_DEVICE_FEATURES_WORD1_MASK,
			UINT32_MAX,
			UINT32_MAX,
		},
	};

	return virtio_features_include(&allowed, feat);
}

/* Ring addresses are in transport space. */
struct virtio_queue_config {
	uint16_t size;
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
};

/* Access direction is from the device's point of view. */
enum virtio_memory_access {
	VIRTIO_MEMORY_READ,
	VIRTIO_MEMORY_WRITE,
};

/* Map a transport-address range to a local virtual-address range. */
struct virtio_mem_region {
	void *va;
	uint64_t address;
	size_t size;
	void *cookie;
};

#endif /* __DRIVERS_VIRTIO_TYPES_H */
