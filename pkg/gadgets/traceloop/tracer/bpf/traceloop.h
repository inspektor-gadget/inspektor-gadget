#ifndef TRACELOOP_H
#define TRACELOOP_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

#define PARAM_LEN 128

/* The syscall can have max 6 arguments. */
#define SYSCALL_ARGS 6

const __u64 PARAM_PROBE_AT_EXIT_MASK = 0xf000000000000000ULL;
const __u64 USE_RET_AS_PARAM_LENGTH = 0x0ffffffffffffffeULL;

/* Special values used to refer to dynamic length. */
const __u64 USE_NULL_BYTE_LENGTH = 0x0fffffffffffffffULL;

/*
 * INDEX(x) is not defined (Cgo cannot access macros),
 * use bit arithmetic with mask below to get value and use addition to generate.
 * The current maximum of parameters is 6, so that means only values until 5 may
 * be added to specify the index. The other theoretical limit is 13 since
 * 14 and 15 are reserved as written above 0xff (null-byte length) and
 * 0xfe (ret as param. length).
 */
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH = 0x0ffffffffffffff0ULL;
const __u64 USE_ARG_INDEX_AS_PARAM_LENGTH_MASK = 0xfULL;

const __u8 SYSCALL_EVENT_TYPE_ENTER = 0;
const __u8 SYSCALL_EVENT_TYPE_EXIT = 1;
const __u8 SYSCALL_EVENT_TYPE_CONT = 2;

struct syscall_event_t {
	/* __u64 ret stored in args[0] */
	__u64 args[SYSCALL_ARGS];
	__u64 timestamp;
	__u64 pid;

	/* how many syscall_event_cont_t messages to expect after */
	char comm[TASK_COMM_LEN];
	__u16 cpu;
	__u16 id;
	__u8 cont_nr;
	__u8 typ;
};

struct syscall_event_cont_t {
	char param[PARAM_LEN];
	__u64 timestamp;
	__u64 length;
	__u8 index;
	__u8 failed;
};

struct syscall_def_t {
	__u64 args_len[SYSCALL_ARGS];
};

struct remembered_args {
	__u64 timestamp;
	__u64 nr;
	__u64 args[SYSCALL_ARGS];
};

#endif
