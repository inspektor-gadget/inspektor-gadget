/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef GADGET_TRACER_MANAGER_COMMON_H
#define GADGET_TRACER_MANAGER_COMMON_H

#define MAX_CONTAINERS_PER_NODE 1024

#define NAME_MAX_LENGTH 256

struct container {
	__u8 container_id[NAME_MAX_LENGTH];
	__u8 namespace[NAME_MAX_LENGTH];
	__u8 pod[NAME_MAX_LENGTH];
	__u8 container[NAME_MAX_LENGTH];
};

#endif
