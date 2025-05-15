/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook, (c) 2022 The Inspektor Gadget authors */
#ifndef __PID_ITER_H
#define __PID_ITER_H

struct pid_iter_entry {
	__u32 id;
	__u32 pid;
	__u8 comm[16];
};

#endif
