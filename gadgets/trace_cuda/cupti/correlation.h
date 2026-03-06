#ifndef CORRELATION_FILTER_H
#define CORRELATION_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* CorrelatorHandle;

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

#ifdef __cplusplus
}
#endif

#endif

