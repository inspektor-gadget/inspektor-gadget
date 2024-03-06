// The test file is the same, creating it to keep a 1:1 relationship between tests and testdata
// files.
#include "populate_metadata_1_tracer_1_struct_from_scratch.bpf.c"

// Multiple tracer with the same name. It will be ignored.
GADGET_TRACER(test, events, event);