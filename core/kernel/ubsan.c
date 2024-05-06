// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <compiler.h>
#include <kernel/panic.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>

struct source_location {
	const char *file_name;
	uint32_t line;
	uint32_t column;
};

struct type_descriptor {
	uint16_t type_kind;
	uint16_t type_info;
	char type_name[1];
};

struct type_mismatch_data {
	struct source_location loc;
	struct type_descriptor *type;
	unsigned long alignment;
	unsigned char type_check_kind;
};

struct overflow_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct shift_out_of_bounds_data {
	struct source_location loc;
	struct type_descriptor *lhs_type;
	struct type_descriptor *rhs_type;
};

struct out_of_bounds_data {
	struct source_location loc;
	struct type_descriptor *array_type;
	struct type_descriptor *index_type;
};

struct unreachable_data {
	struct source_location loc;
};

struct vla_bound_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct invalid_value_data {
	struct source_location loc;
	struct type_descriptor *type;
};

struct nonnull_arg_data {
	struct source_location loc;
};

/*
 * When compiling with -fsanitize=undefined the compiler expects functions
 * with the following signatures. The functions are never called directly,
 * only when undefined behavior is detected in instrumented code.
 */
void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				  unsigned long ptr);
void __ubsan_handle_type_mismatch_v1(struct type_mismatch_data *data,
				     unsigned long ptr);
void __ubsan_handle_add_overflow(struct overflow_data *data,
				  unsigned long lhs, unsigned long rhs);
void __ubsan_handle_sub_overflow(struct overflow_data *data,
				  unsigned long lhs, unsigned long rhs);
void __ubsan_handle_mul_overflow(struct overflow_data *data,
				  unsigned long lhs, unsigned long rhs);
void __ubsan_handle_negate_overflow(struct overflow_data *data,
				    unsigned long old_val);
void __ubsan_handle_divrem_overflow(struct overflow_data *data,
				    unsigned long lhs, unsigned long rhs);
void __ubsan_handle_pointer_overflow(struct overflow_data *data,
				     unsigned long lhs, unsigned long rhs);
void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
					unsigned long lhs, unsigned long rhs);
void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data,
				  unsigned long idx);
void __ubsan_handle_unreachable(struct unreachable_data *data);
void __ubsan_handle_missing_return(struct unreachable_data *data);
void __ubsan_handle_vla_bound_not_positive(struct vla_bound_data *data,
					   unsigned long bound);
void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
				       unsigned long val);
void __ubsan_handle_nonnull_arg(struct nonnull_arg_data *data
#if __GCC_VERSION < 60000
				, size_t arg_no
#endif
			       );

static void print_loc(const char *func, struct source_location *loc)
{
	const char *f = func;
	const char func_prefix[] = "__ubsan_handle";

	if (!memcmp(f, func_prefix, sizeof(func_prefix) - 1))
		f += sizeof(func_prefix);

	EMSG_RAW("Undefined behavior %s at %s:%" PRIu32 " col %" PRIu32,
		 f, loc->file_name, loc->line, loc->column);
}


static volatile bool ubsan_panic = true;

void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				  unsigned long ptr __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_type_mismatch_v1(struct type_mismatch_data *data,
				     unsigned long ptr __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_add_overflow(struct overflow_data *data,
				 unsigned long lhs __unused,
				 unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_sub_overflow(struct overflow_data *data,
				 unsigned long lhs __unused,
				 unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_mul_overflow(struct overflow_data *data,
				 unsigned long lhs __unused,
				 unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_negate_overflow(struct overflow_data *data,
				    unsigned long old_val __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_divrem_overflow(struct overflow_data *data,
				    unsigned long lhs __unused,
				    unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_pointer_overflow(struct overflow_data *data,
				     unsigned long lhs __unused,
				     unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
					unsigned long lhs __unused,
					unsigned long rhs __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data,
				  unsigned long idx __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_unreachable(struct unreachable_data *data)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __noreturn __ubsan_handle_missing_return(struct unreachable_data *data)
{
	print_loc(__func__, &data->loc);
	panic();
}

void __ubsan_handle_vla_bound_not_positive(struct vla_bound_data *data,
					   unsigned long bound __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
				       unsigned long val __unused)
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}

void __ubsan_handle_nonnull_arg(struct nonnull_arg_data *data
#if __GCC_VERSION < 60000
				, size_t arg_no __unused
#endif
			       )
{
	print_loc(__func__, &data->loc);
	if (ubsan_panic)
		panic();
}
