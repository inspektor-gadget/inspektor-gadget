#ifndef GADGET_TRACER_MANAGER_COMMON_H
#define GADGET_TRACER_MANAGER_COMMON_H

#define MAX_CONTAINER_PER_NODE 1024

#define NAME_MAX_LENGTH 256

struct container {
	char container_id[NAME_MAX_LENGTH];
	char kubernetes_namespace[NAME_MAX_LENGTH];
	char kubernetes_pod[NAME_MAX_LENGTH];
	char kubernetes_container[NAME_MAX_LENGTH];
};

#endif
