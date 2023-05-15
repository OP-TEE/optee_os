/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020-2021 NXP
 *
 * CAAM DMA data object utilities include file.
 */
#ifndef __CAAM_UTILS_DMAOBJ_H__
#define __CAAM_UTILS_DMAOBJ_H__

#include <caam_types.h>
#include <caam_utils_sgt.h>
#include <tee_api_types.h>

/*
 * CAAM DMA Object type
 * @priv   Private object data not used externally.
 * @orig   Original data buffer
 * @sgtbuf CAAM SGT/Buffer object
 */
struct caamdmaobj {
	void *priv;
	struct caambuf orig;
	struct caamsgtbuf sgtbuf;
};

/*
 * Initialize a CAAM DMA object of type input data.
 * If necessary, a new CAAM Buffer will be reallocated if given @data is not
 * accessible by the CAAM DMA and input data copied into.
 *
 * @obj     [out] CAAM DMA object initialized
 * @data    Input data pointer
 * @length  Length in bytes of the input data
 */
TEE_Result caam_dmaobj_init_input(struct caamdmaobj *obj, const void *data,
				  size_t len);
/*
 * Initialize and build the SGT/Buffer Object of a CAAM DMA object of type
 * input data.
 * Function call the caam_dmaobj_init_input function and if success
 * the caam_dmaobj_sgtbuf_build function. If the full size of the input
 * data can't be handled in the SGT/Buffer Object, returns in error.
 *
 * @obj     [out] CAAM DMA object initialized
 * @data    Input data pointer
 * @length  Length in bytes of the input data
 */
TEE_Result caam_dmaobj_input_sgtbuf(struct caamdmaobj *obj, const void *data,
				    size_t len);
/*
 * Initialize a CAAM DMA object of type output data.
 * If necessary, a new CAAM Buffer will be reallocated if given @data is not
 * accessible by the CAAM DMA or if the given @length is lower than
 * @min_length requested for the CAAM operation.
 *
 * @obj         [out] CAAM DMA object initialized
 * @data        Output data pointer
 * @length      Length in bytes of the output data
 * @min_length  Minimum length in bytes needed for the output data
 */
TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, void *data,
				   size_t length, size_t min_length);

/*
 * Initialize and build the SGT/Buffer Object of a CAAM DMA object of type
 * output data.
 * Function call the caam_dmaobj_init_output function and if success
 * the caam_dmaobj_sgtbuf_build function. If the full size of the output
 * data can't be handled in the SGT/Buffer Object, returns in error.
 *
 * Note: to allocate a output buffer, set @data = NULL and length = 0, the
 * buffer size allocated will be the @min_length size. Caution, the field
 * orig of the @obj is kept empty.
 *
 * @obj         [out] CAAM DMA object initialized
 * @data        Output data pointer
 * @length      Length in bytes of the output data
 * @min_length  Minimum length in bytes needed for the output data
 */
TEE_Result caam_dmaobj_output_sgtbuf(struct caamdmaobj *obj, void *data,
				     size_t length, size_t min_length);

/*
 * Push the data to physical memory with a cache clean or flush depending
 * on the type of data, respectively input or output.
 *
 * @obj     CAAM DMA object
 */
void caam_dmaobj_cache_push(struct caamdmaobj *obj);

/*
 * Copy the CAAM DMA object buffer to the original data buffer.
 * Return the number of bytes copied.
 *
 * @obj     CAAM DMA object
 */
size_t caam_dmaobj_copy_to_orig(struct caamdmaobj *obj);

/*
 * Copy the CAAM DMA object buffer to the original data buffer removing
 * non-significant first zeros (left zeros).
 * If all DMA object buffer is zero, left only one zero in the destination.
 * Return the number of bytes copied.
 *
 * @obj    CAAM DMA object
 */
size_t caam_dmaobj_copy_ltrim_to_orig(struct caamdmaobj *obj);

/*
 * Free the CAAM DMA object.
 * If a buffer has been reallocated, free it.
 * Free the sgtbuf object.
 *
 * @obj     CAAM DMA object
 */
void caam_dmaobj_free(struct caamdmaobj *obj);

/*
 * Create a CAAM DMA object SGT type with the block buffer @block first and
 * the CAAM DMA Object after
 *
 * @res     CAAM DMA object resulting
 * @block   CAAM Block buffer to add first
 * @obj     CAAM DMA object to add secondly
 */
TEE_Result caam_dmaobj_add_first_block(struct caamdmaobj *obj,
				       struct caamblock *block);

/*
 * Derive a CAAM DMA object's sgtbuf object to a new DMA object.
 * The @from CAAM DMA object sgtbuf must have to be created first to
 * allocate the DMA Buffers.
 *
 * @obj     [out] CAAM DMA object derived
 * @from    Original CAAM DMA object
 * @offset  Offset to start from
 * @length  Length in bytes of the data
 */
TEE_Result caam_dmaobj_derive_sgtbuf(struct caamdmaobj *obj,
				     const struct caamdmaobj *from,
				     size_t offset, size_t length);

/*
 * Build the CAAM DMA Object's sgtbuf input and output with the same data
 * length.
 * First try to build input sgtbuf of maximum @length starting at @offset.
 * Then build output sgtbuf with same input data length built start at @offset.
 * If output sgtbuf built data length is not the same as the input's one,
 * rebuild the input with same output data length.
 *
 * If the both input and output length are not equal returns an error.
 *
 * @input   CAAM DMA Input object
 * @output  CAAM DMA Output object
 * @length  [in/out] maximum length to do/done
 * @off     Starting offset
 * @align   Buffer allocation alignment
 */
TEE_Result caam_dmaobj_sgtbuf_inout_build(struct caamdmaobj *input,
					  struct caamdmaobj *output,
					  size_t *length, size_t off,
					  size_t align);

/*
 * Prepare input/output CAAM DMA Object's by allocating the DMA Buffers
 * if needed.
 * If @input or @output is NULL, allocates DMA buffer of given object.
 * Else if both objects are set, allocates DMA buffer of the same
 * size for the @input and @output objects.
 * Minimum DMA Buffer size allocated is the @min_size value. Even if this
 * minimum size allocation failed, returns an error.
 *
 * @input     CAAM DMA object input
 * @output    CAAM DMA object output
 * @min_size  Mimimum length to allocate
 */
TEE_Result caam_dmaobj_prepare(struct caamdmaobj *input,
			       struct caamdmaobj *output, size_t min_size);

/*
 * Build the CAAM DMA Object's sgtbuf object. Try to build a sgtbuf of
 * maximum @length starting at @offset.
 * Return the @length mapped in the sgtbuf object.
 *
 * @obj     CAAM DMA object
 * @length  [in/out] maximum length to do/done
 * @off     Starting offset
 * @align   Buffer allocation alignment
 */
TEE_Result caam_dmaobj_sgtbuf_build(struct caamdmaobj *obj, size_t *length,
				    size_t off, size_t align);

#endif /* __CAAM_UTILS_DMAOBJ_H__ */
