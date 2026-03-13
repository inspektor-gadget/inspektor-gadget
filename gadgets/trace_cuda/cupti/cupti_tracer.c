#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <cupti.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sdt.h>
#include "correlation.h"
#include <time.h>

#define CUPTI_CALL(call)                                                \
  do {                                                                  \
    CUptiResult _status = call;                                         \
    if (_status != CUPTI_SUCCESS) {                                     \
      const char *errstr;                                               \
      cuptiGetResultString(_status, &errstr);                           \
      fprintf(stderr, "%s:%d: error: function %s failed with error %s.\n", \
              __FILE__, __LINE__, #call, errstr);                       \
    }                                                                   \
  } while (0)

#define CUPTI_CALL_ABORT_RET(call, ret)                                 \
  do {                                                                   \
    CUptiResult _status = (call);                                        \
    if (_status != CUPTI_SUCCESS) {                                      \
      const char *errstr = NULL;                                          \
      cuptiGetResultString(_status, &errstr);                            \
      fprintf(stderr, "[CUPTI:FATAL] %s:%d: %s failed: %s\n",            \
              __FILE__, __LINE__, #call,                                  \
              errstr ? errstr : "unknown");                              \
      return (ret);                                                      \
    }                                                                    \
  } while (0)


#define BUF_SIZE (128 * 1024)
#define ALIGN_SIZE (8)

static uint64_t startTimestamp = 0;
static CUpti_SubscriberHandle subscriber = 0;

static CorrelatorHandle filter = NULL;

static __thread uint32_t runtimeEnterCorrelationId = 0;

static bool debug_enabled = false;
static bool debug_initialized = false;

static void init_debug(void) {
  if (!debug_initialized) {
    debug_enabled = getenv("CUPTI_TRACER_DEBUG") != NULL;
    debug_initialized = true;
  }
}

#define DEBUG_PRINTF(...)                                                     \
  do {                                                                        \
    init_debug();                                                             \
    if (debug_enabled) {                                                      \
      struct timespec ts;                                                     \
      clock_gettime(CLOCK_REALTIME, &ts);                                     \
      fprintf(stderr, "[%ld.%09ld] ", ts.tv_sec, ts.tv_nsec);                 \
      fprintf(stderr, __VA_ARGS__);                                           \
    }                                                                         \
  } while (0)

static inline uint64_t cpu_time_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void CUPTIAPI bufferRequested(uint8_t **buffer , size_t *size,size_t *maxNumRecords){
  *buffer = (uint8_t *)aligned_alloc(ALIGN_SIZE,BUF_SIZE);
  *size = BUF_SIZE;
  *maxNumRecords = 0;
}

static void CUPTIAPI  bufferCompleted(CUcontext ctx, uint32_t streamId, uint8_t *buffer, size_t size, size_t validSize){
  CUptiResult result;
  CUpti_Activity *record = NULL;

  if(validSize >0){
    do{
      result = cuptiActivityGetNextRecord(buffer, validSize,&record);
      if (result == CUPTI_SUCCESS){
        if(record->kind == CUPTI_ACTIVITY_KIND_KERNEL || record->kind == CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL){
          CUpti_ActivityKernel9 *kernel = (CUpti_ActivityKernel9 *) record;
          
          bool send = true;
          if(filter){
            send = correlator_check_and_remove(filter, kernel->correlationId);
          }


          if (send){
            uint64_t grid_xy =
                ((uint64_t)kernel->gridX << 32) |
                 (uint64_t)kernel->gridY;

            uint64_t block_xy =
                ((uint64_t)kernel->blockX << 32) |
                 (uint64_t)kernel->blockY;

            double start = (kernel->start - startTimestamp) / 1e6;
            double end   = (kernel->end   - startTimestamp) / 1e6;
            double dur   = (kernel->end - kernel->start) / 1e6;

            DEBUG_PRINTF("\n=== Kernel Launch ===\n");
            DEBUG_PRINTF("Name: %s\n", kernel->name);
            DEBUG_PRINTF("Grid: %u x %u x %u\n",
                   kernel->gridX, kernel->gridY, kernel->gridZ);
            DEBUG_PRINTF("Block: %u x %u x %u\n",
                   kernel->blockX, kernel->blockY, kernel->blockZ);
            DEBUG_PRINTF("Start (ms): %.3f\n", start);
            DEBUG_PRINTF("End   (ms): %.3f\n", end);
            DEBUG_PRINTF("Duration (ms): %.3f\n", dur);

            
            DEBUG_PRINTF("\n=== Correlated Kernel ===\n");
            DEBUG_PRINTF("Correlation ID: %u\n", kernel->correlationId);
          
            DEBUG_PRINTF("Stream ID: %u\n", kernel->streamId);

            DTRACE_PROBE9(myprov, ig_activity, kernel->correlationId,
                           kernel->start,
                           kernel->end,
                           kernel->deviceId,
                           kernel->streamId,
                           grid_xy,
                           kernel->gridZ,
                           block_xy,
                           kernel->blockZ);
          }
          
        }
      }
      else if(result == CUPTI_ERROR_MAX_LIMIT_REACHED){
        break;
      }
      else{
        DEBUG_PRINTF("Error reading activity record\n");
        break;
      }
    }while (1);
  }

  free(buffer);

  size_t dropped;
  CUPTI_CALL(cuptiActivityGetNumDroppedRecords(ctx, streamId, &dropped));
  if (dropped != 0) {
    DEBUG_PRINTF("Dropped %zu activity records\n", dropped);
  }
}

static void CUPTIAPI cuptiCallback(void *userdata, CUpti_CallbackDomain domain,
                                    CUpti_CallbackId cbid, const CUpti_CallbackData *cbInfo){

  uint32_t correlationId = cbInfo->correlationId;

  const char *name = cbInfo->symbolName ? cbInfo->symbolName : cbInfo->functionName;

  bool emit = false;
  uint64_t result_value = 0;

  if( domain == CUPTI_CB_DOMAIN_RUNTIME_API && cbInfo->callbackSite == CUPTI_API_ENTER){
    runtimeEnterCorrelationId = correlationId;
    return;
  }

  if(cbInfo->callbackSite != CUPTI_API_EXIT){
    return;
  }

  if( domain == CUPTI_CB_DOMAIN_DRIVER_API){
    if (correlationId == runtimeEnterCorrelationId)
      return;

    switch (cbid) {
      case CUPTI_DRIVER_TRACE_CBID_cuLaunch:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchGrid:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchGridAsync:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel_ptsz:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx_ptsz:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel_ptsz:
      case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernelMultiDevice:
      case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch:
      case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz:
      {
        CUresult result = cbInfo->functionReturnValue? *(CUresult *)cbInfo->functionReturnValue: CUDA_SUCCESS;

        DEBUG_PRINTF("\n[Driver EXIT] cuLaunchKernel\n");
        DEBUG_PRINTF("Correlation ID: %u\n", correlationId);
        DEBUG_PRINTF("Kernel: %s\n", name);
        DEBUG_PRINTF("Return value: %d\n", result);
        DEBUG_PRINTF("cbid: %u\n", cbid);

        result_value = (uint64_t)result;
        emit = true;
        if(filter)
          correlator_insert(filter, correlationId);

        break;
      }
    }
      

  }
  else if( domain == CUPTI_CB_DOMAIN_RUNTIME_API){

    switch (cbid){
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_v3020:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_ptsz_v7000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_v11060:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_ptsz_v11060:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_v9000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_ptsz_v9000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernelMultiDevice_v9000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000:
      case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000:
      {
        cudaError_t result = cbInfo->functionReturnValue? *(cudaError_t *)cbInfo->functionReturnValue: cudaSuccess;

        DEBUG_PRINTF("\n[Runtime EXIT] cudaLaunchKernel\n");
        DEBUG_PRINTF("Correlation ID: %u\n", correlationId);
        DEBUG_PRINTF("Kernel: %s\n", name);
        DEBUG_PRINTF("Return value: %d\n", result);
        DEBUG_PRINTF("cbid: %u\n", cbid);

        result_value = (uint64_t)result;
        emit = true;
        if (filter)
          correlator_insert(filter, correlationId);
        
        break;
      }
    }

    runtimeEnterCorrelationId = 0;

  }

  if(emit){
     DTRACE_PROBE4(myprov, ig_callback,
      correlationId,
      (uint32_t)cbid,
      name,
      result_value);
  }
}

void cleanup(void){
  static bool cleanup_done = false;

  // Make cleanup idempotent - safe to call multiple times
  if (cleanup_done) {
    return;
  }
  cleanup_done = true;

  cuptiActivityFlushAll(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);

  if (subscriber) {
    cuptiUnsubscribe(subscriber);
    subscriber = 0;
  }

  if(filter){
     size_t remaining = correlator_size(filter);
    if (remaining > 0) {
      DEBUG_PRINTF("[CUPTI] Warning: %zu correlation IDs still in filter at cleanup\n", remaining);
    }
    correlator_destroy(filter);
    filter= NULL;
  }

  DEBUG_PRINTF("Cleanup complet \n");
}

int InitializeInjection(void){

  CUPTI_CALL(cuptiActivityFlushAll(1000));

  CUPTI_CALL_ABORT_RET(cuptiSubscribe(&subscriber, (CUpti_CallbackFunc)cuptiCallback, NULL),1);

  CUpti_CallbackId runtimeCallbacks[] = {
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_v3020,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_ptsz_v7000,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_v11060,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_ptsz_v11060,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_v9000,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_ptsz_v9000,
    CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernelMultiDevice_v9000,
    CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000,
    CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000,
  };

  for (size_t i = 0; i < sizeof(runtimeCallbacks)/sizeof(runtimeCallbacks[0]); i++){
    CUPTI_CALL(cuptiEnableCallback(1, subscriber, CUPTI_CB_DOMAIN_RUNTIME_API, runtimeCallbacks[i]));
  }

  CUpti_CallbackId driverCallbacks[] = {
    CUPTI_DRIVER_TRACE_CBID_cuLaunch,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchGrid,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchGridAsync,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel_ptsz,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx_ptsz,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel_ptsz,
    CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernelMultiDevice,
    CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch,
    CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz,
  };

  for (size_t i = 0 ; i< sizeof(driverCallbacks)/sizeof(driverCallbacks[0]);i++){
    CUPTI_CALL(cuptiEnableCallback(1, subscriber, CUPTI_CB_DOMAIN_DRIVER_API,driverCallbacks[i] ));
  }

  CUPTI_CALL(cuptiActivityEnable(CUPTI_ACTIVITY_KIND_KERNEL));

  CUPTI_CALL(cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL));

  CUPTI_CALL_ABORT_RET(cuptiActivityRegisterCallbacks(bufferRequested,bufferCompleted ),1);

  CUPTI_CALL(cuptiGetTimestamp(&startTimestamp));

  filter = correlator_create();

  atexit(cleanup);
  return 1;
}

