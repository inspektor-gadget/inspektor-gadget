#ifndef CORRELATION_FILTER_H
#define CORRELATION_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* CorrelatorHandle;
typedef void* GraphMapHandle;

// Create / destroy
CorrelatorHandle correlator_create(void);
void correlator_destroy(CorrelatorHandle filter);

// Insert correlation ID
void correlator_insert(CorrelatorHandle filter,
                               uint32_t correlation_id);

// Check and remove (atomic)
bool correlator_check_and_remove(CorrelatorHandle filter,
                                         uint32_t correlation_id);

// Size (optional, useful for debugging)
size_t correlator_size(CorrelatorHandle filter);

enum GraphState {
  GRAPH_UNINITIALIZED = 0, // Entry just created, slot not yet processed
  GRAPH_CYCLE_CLEARED = 1, // Cycle started, no kernels seen yet
  GRAPH_KERNEL_SEEN = 2    // At least one kernel seen this cycle
};

GraphMapHandle graph_map_create(void);
void graph_map_destroy(GraphMapHandle map);
void graph_map_insert(GraphMapHandle map, uint32_t cid);
void graph_map_cycle_start(GraphMapHandle map, uint32_t cycle);
bool graph_map_mark_seen_cycle(GraphMapHandle map,uint32_t cid, uint32_t cycle);
void graph_map_finish_cycle(GraphMapHandle map);
void graph_map_get_stat(GraphMapHandle map, size_t* size, size_t* old_age);
size_t graph_map_size(GraphMapHandle map);
#ifdef __cplusplus
}
#endif

#endif

