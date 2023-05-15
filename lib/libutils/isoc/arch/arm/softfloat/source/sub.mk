incdirs-lib-y += include
incdirs-lib-y += 8086-SSE
subdirs-y += 8086-SSE

cflags-y += -Wno-aggregate-return
cflags-y += -Wno-sign-compare
cflags-y += -Wno-missing-prototypes
cflags-y += -Wno-missing-declarations

srcs-y += f32_add.c
srcs-y += f32_div.c
srcs-y += f32_eq.c
srcs-y += f32_le.c
srcs-y += f32_lt.c
srcs-y += f32_mul.c
srcs-y += f32_sub.c
srcs-y += f32_to_f64.c
srcs-y += f32_to_i32_r_minMag.c
srcs-y += f32_to_i64_r_minMag.c
srcs-y += f32_to_ui32_r_minMag.c
srcs-y += f32_to_ui64_r_minMag.c

srcs-y += f64_add.c
srcs-y += f64_div.c
srcs-y += f64_eq.c
srcs-y += f64_le.c
srcs-y += f64_lt.c
srcs-y += f64_mul.c
srcs-y += f64_sub.c
srcs-y += f64_to_f32.c
srcs-y += f64_to_i32_r_minMag.c
srcs-y += f64_to_i64_r_minMag.c
srcs-y += f64_to_ui32_r_minMag.c
srcs-y += f64_to_ui64_r_minMag.c

srcs-y += i32_to_f32.c
srcs-y += i32_to_f64.c
srcs-y += i64_to_f32.c
srcs-y += i64_to_f64.c
srcs-y += ui32_to_f32.c
srcs-y += ui32_to_f64.c
srcs-y += ui64_to_f32.c
srcs-y += ui64_to_f64.c

srcs-y += s_subMagsF32.c
srcs-y += s_subMagsF64.c
srcs-y += s_addMagsF32.c
srcs-y += s_addMagsF64.c
srcs-y += s_normSubnormalF64Sig.c
srcs-y += s_normSubnormalF32Sig.c
srcs-y += s_roundPackToF32.c
srcs-y += s_roundPackToF64.c
srcs-y += s_shortShiftRightJam64.c
srcs-y += s_shiftRightJam32.c
srcs-y += s_normRoundPackToF32.c
srcs-y += s_normRoundPackToF64.c
srcs-y += s_shiftRightJam64.c

srcs-y += s_countLeadingZeros8.c
srcs-y += s_countLeadingZeros32.c
srcs-y += s_countLeadingZeros64.c

srcs-y += s_mul64To128.c

srcs-y += softfloat_state.c
