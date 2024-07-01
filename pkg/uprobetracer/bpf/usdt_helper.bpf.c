// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define USDT_ARG_MAGIC 0xA
#define USDT_ARG_MAX_COUNT 12

enum USDT_ARG_TYPE {
	/* Argument in register */
	USDT_ARG_TYPE_REG,
	/* Argument in memory */
	USDT_ARG_TYPE_MEM,
};

enum USDT_ARG_LENGTH {
	USDT_ARG_LENGTH_UINT8 = 0,
	USDT_ARG_LENGTH_INT8,
	USDT_ARG_LENGTH_UINT16,
	USDT_ARG_LENGTH_INT16,
	USDT_ARG_LENGTH_UINT32,
	USDT_ARG_LENGTH_INT32,
	USDT_ARG_LENGTH_UINT64,
	USDT_ARG_LENGTH_INT64,
};

// using inline asm to avoid the "dereference of modified ctx ptr" error,
// see https://mejedi.dev/posts/ebpf-dereference-of-modified-ctx-ptr-disallowed/
#define RETURN_CTX_FIELD(field)                                      \
	{                                                            \
		u64 buf;                                             \
		asm("%[res] = *(u64 *)(%[base] + %[offset])"         \
		    : [res] "=r"(buf)                                \
		    : [base] "r"(ctx),                               \
		      [offset] "i"(offsetof(struct pt_regs, field)), \
		      "m"(*ctx));                                    \
		return buf;                                          \
	}

#if defined(__TARGET_ARCH_arm64)

enum USDT_ARG_REG {
	USDT_ARG_REG_ZERO,
	USDT_ARG_REG_R0,
	USDT_ARG_REG_R1,
	USDT_ARG_REG_R2,
	USDT_ARG_REG_R3,
	USDT_ARG_REG_R4,
	USDT_ARG_REG_R5,
	USDT_ARG_REG_R6,
	USDT_ARG_REG_R7,
	USDT_ARG_REG_R8,
	USDT_ARG_REG_R9,
	USDT_ARG_REG_R10,
	USDT_ARG_REG_R11,
	USDT_ARG_REG_R12,
	USDT_ARG_REG_R13,
	USDT_ARG_REG_R14,
	USDT_ARG_REG_R15,
	USDT_ARG_REG_R16,
	USDT_ARG_REG_R17,
	USDT_ARG_REG_R18,
	USDT_ARG_REG_R19,
	USDT_ARG_REG_R20,
	USDT_ARG_REG_R21,
	USDT_ARG_REG_R22,
	USDT_ARG_REG_R23,
	USDT_ARG_REG_R24,
	USDT_ARG_REG_R25,
	USDT_ARG_REG_R26,
	USDT_ARG_REG_R27,
	USDT_ARG_REG_R28,
	USDT_ARG_REG_R29,
	USDT_ARG_REG_R30,
	USDT_ARG_REG_SP,
	USDT_ARG_REG_PC,
	USDT_ARG_REG_PSTATE,
};

static __always_inline __u64 usdt_get_register_val(const struct pt_regs *_ctx,
						   unsigned reg_id)
{
	const struct user_pt_regs *ctx = (const struct user_pt_regs *)_ctx;
	switch (reg_id) {
	case USDT_ARG_REG_ZERO:
		return 0;
	case USDT_ARG_REG_R0:
		return ctx->regs[0];
	case USDT_ARG_REG_R1:
		return ctx->regs[1];
	case USDT_ARG_REG_R2:
		return ctx->regs[2];
	case USDT_ARG_REG_R3:
		return ctx->regs[3];
	case USDT_ARG_REG_R4:
		return ctx->regs[4];
	case USDT_ARG_REG_R5:
		return ctx->regs[5];
	case USDT_ARG_REG_R6:
		return ctx->regs[6];
	case USDT_ARG_REG_R7:
		return ctx->regs[7];
	case USDT_ARG_REG_R8:
		return ctx->regs[8];
	case USDT_ARG_REG_R9:
		return ctx->regs[9];
	case USDT_ARG_REG_R10:
		return ctx->regs[10];
	case USDT_ARG_REG_R11:
		return ctx->regs[11];
	case USDT_ARG_REG_R12:
		return ctx->regs[12];
	case USDT_ARG_REG_R13:
		return ctx->regs[13];
	case USDT_ARG_REG_R14:
		return ctx->regs[14];
	case USDT_ARG_REG_R15:
		return ctx->regs[15];
	case USDT_ARG_REG_R16:
		return ctx->regs[16];
	case USDT_ARG_REG_R17:
		return ctx->regs[17];
	case USDT_ARG_REG_R18:
		return ctx->regs[18];
	case USDT_ARG_REG_R19:
		return ctx->regs[19];
	case USDT_ARG_REG_R20:
		return ctx->regs[20];
	case USDT_ARG_REG_R21:
		return ctx->regs[21];
	case USDT_ARG_REG_R22:
		return ctx->regs[22];
	case USDT_ARG_REG_R23:
		return ctx->regs[23];
	case USDT_ARG_REG_R24:
		return ctx->regs[24];
	case USDT_ARG_REG_R25:
		return ctx->regs[25];
	case USDT_ARG_REG_R26:
		return ctx->regs[26];
	case USDT_ARG_REG_R27:
		return ctx->regs[27];
	case USDT_ARG_REG_R28:
		return ctx->regs[28];
	case USDT_ARG_REG_R29:
		return ctx->regs[29];
	case USDT_ARG_REG_R30:
		return ctx->regs[30];
	case USDT_ARG_REG_SP:
		return ctx->sp;
	case USDT_ARG_REG_PC:
		return ctx->pc;
	case USDT_ARG_REG_PSTATE:
		return ctx->pstate;
	default:
		return 0;
	}
}

#elif defined(__TARGET_ARCH_x86)

enum USDT_ARG_REG {
	USDT_ARG_REG_ZERO,
	USDT_ARG_REG_R15,
	USDT_ARG_REG_R14,
	USDT_ARG_REG_R13,
	USDT_ARG_REG_R12,
	USDT_ARG_REG_BP,
	USDT_ARG_REG_BX,
	USDT_ARG_REG_R11,
	USDT_ARG_REG_R10,
	USDT_ARG_REG_R9,
	USDT_ARG_REG_R8,
	USDT_ARG_REG_AX,
	USDT_ARG_REG_CX,
	USDT_ARG_REG_DX,
	USDT_ARG_REG_SI,
	USDT_ARG_REG_DI,
	USDT_ARG_REG_ORIG_AX,
	USDT_ARG_REG_IP,
	USDT_ARG_REG_CS,
	USDT_ARG_REG_FLAGS,
	USDT_ARG_REG_SP,
	USDT_ARG_REG_SS,
};

static __always_inline __u64 usdt_get_register_val(const struct pt_regs *ctx,
						   unsigned reg_id)
{
	switch (reg_id) {
	case USDT_ARG_REG_ZERO:
		return 0;
	case USDT_ARG_REG_R15:
		RETURN_CTX_FIELD(r15);
	case USDT_ARG_REG_R14:
		RETURN_CTX_FIELD(r14);
	case USDT_ARG_REG_R13:
		RETURN_CTX_FIELD(r13);
	case USDT_ARG_REG_R12:
		RETURN_CTX_FIELD(r12);
	case USDT_ARG_REG_BP:
		RETURN_CTX_FIELD(bp);
	case USDT_ARG_REG_BX:
		RETURN_CTX_FIELD(bx);
	case USDT_ARG_REG_R11:
		RETURN_CTX_FIELD(r11);
	case USDT_ARG_REG_R10:
		RETURN_CTX_FIELD(r10);
	case USDT_ARG_REG_R9:
		RETURN_CTX_FIELD(r9);
	case USDT_ARG_REG_R8:
		RETURN_CTX_FIELD(r8);
	case USDT_ARG_REG_AX:
		RETURN_CTX_FIELD(ax);
	case USDT_ARG_REG_CX:
		RETURN_CTX_FIELD(cx);
	case USDT_ARG_REG_DX:
		RETURN_CTX_FIELD(dx);
	case USDT_ARG_REG_SI:
		RETURN_CTX_FIELD(si);
	case USDT_ARG_REG_DI:
		RETURN_CTX_FIELD(di);
	case USDT_ARG_REG_ORIG_AX:
		RETURN_CTX_FIELD(orig_ax);
	case USDT_ARG_REG_IP:
		RETURN_CTX_FIELD(ip);
	case USDT_ARG_REG_CS:
		RETURN_CTX_FIELD(cs);
	case USDT_ARG_REG_FLAGS:
		RETURN_CTX_FIELD(flags);
	case USDT_ARG_REG_SP:
		RETURN_CTX_FIELD(sp);
	case USDT_ARG_REG_SS:
		RETURN_CTX_FIELD(ss);
	default:
		return 0;
	}
}

#else
#error "USDT argument support is not supported in the current architecture."
#endif

/* Some more complex USDT parameters may require multiple registers */
/* We use 64 bits for future scalability */
struct __usdt_argument {
	unsigned magic : 4;
	enum USDT_ARG_TYPE type : 1;
	enum USDT_ARG_LENGTH length : 3;
	enum USDT_ARG_REG reg : 8;
	int offset : 16;
	unsigned _padding : 32;
};

struct __usdt_arguments {
	struct __usdt_argument arguments[USDT_ARG_MAX_COUNT];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} __usdt_args_buffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct __usdt_arguments));
	__uint(max_entries, 10000);
} __usdt_args_info SEC(".maps");

/* Returns true if the argument value is stored in the above map successfully, otherwise returns false */
/* The buffer will be reused, so users need to store the value before next call */
SEC("freplace/__usdt_get_argument")
bool __usdt_get_argument(struct pt_regs *ctx, u64 arg_idx)
{
	u64 cookie = bpf_get_attach_cookie(ctx);
	if (!cookie)
		return false;

	u32 zero = 0;
	u64 *buffer = bpf_map_lookup_elem(&__usdt_args_buffer, &zero);
	if (!buffer)
		return false;

	const struct __usdt_arguments *args =
		bpf_map_lookup_elem(&__usdt_args_info, &cookie);
	if (!args)
		return false;

	if (arg_idx >= USDT_ARG_MAX_COUNT)
		return false;

	const struct __usdt_argument arg = args->arguments[arg_idx];
	if (arg.magic != USDT_ARG_MAGIC)
		return false;

	u64 register_val = usdt_get_register_val(ctx, arg.reg);
	u64 offset_val = arg.offset;

#define COPY_REG_VALUE_AND_RETURN(type) \
	*buffer = (type)register_val;   \
	return true;

	switch (arg.type) {
	case USDT_ARG_TYPE_REG:
		switch (arg.length) {
		case USDT_ARG_LENGTH_UINT8:
			COPY_REG_VALUE_AND_RETURN(uint8_t)
		case USDT_ARG_LENGTH_INT8:
			COPY_REG_VALUE_AND_RETURN(int8_t)
		case USDT_ARG_LENGTH_UINT16:
			COPY_REG_VALUE_AND_RETURN(uint16_t)
		case USDT_ARG_LENGTH_INT16:
			COPY_REG_VALUE_AND_RETURN(int16_t)
		case USDT_ARG_LENGTH_UINT32:
			COPY_REG_VALUE_AND_RETURN(uint32_t)
		case USDT_ARG_LENGTH_INT32:
			COPY_REG_VALUE_AND_RETURN(int32_t)
		case USDT_ARG_LENGTH_UINT64:
			COPY_REG_VALUE_AND_RETURN(uint64_t)
		case USDT_ARG_LENGTH_INT64:
			COPY_REG_VALUE_AND_RETURN(int64_t)
		default:
			return false;
		}
	case USDT_ARG_TYPE_MEM: {
		u64 memory_address = register_val + offset_val;
		u64 buf;

#define COPY_MEM_VALUE_AND_RETURN(type)                                      \
	if (bpf_probe_read_user(&buf, sizeof(type), (void *)memory_address)) \
		return false;                                                \
	*buffer = *(type *)&buf;                                             \
	return true;

		switch (arg.length) {
		case USDT_ARG_LENGTH_UINT8:
			COPY_MEM_VALUE_AND_RETURN(uint8_t)
		case USDT_ARG_LENGTH_INT8:
			COPY_MEM_VALUE_AND_RETURN(int8_t)
		case USDT_ARG_LENGTH_UINT16:
			COPY_MEM_VALUE_AND_RETURN(uint16_t)
		case USDT_ARG_LENGTH_INT16:
			COPY_MEM_VALUE_AND_RETURN(int16_t)
		case USDT_ARG_LENGTH_UINT32:
			COPY_MEM_VALUE_AND_RETURN(uint32_t)
		case USDT_ARG_LENGTH_INT32:
			COPY_MEM_VALUE_AND_RETURN(int32_t)
		case USDT_ARG_LENGTH_UINT64:
			COPY_MEM_VALUE_AND_RETURN(uint64_t)
		case USDT_ARG_LENGTH_INT64:
			COPY_MEM_VALUE_AND_RETURN(int64_t)
		}
	}
	default:
		return false;
	}
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
