// The test file is the same, creating it to keep a 1:1 relationship between tests and testdata
// files.
#include "populate_metadata_1_topper_1_struct_from_scratch.bpf.c"

// Multiple toppers are not supported, so this should be ignored
GADGET_TOPPER(ignored_topper, events);
