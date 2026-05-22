
# trace_cuda – CUPTI Userspace Library

## Overview

This directory contains a **CUPTI-based userspace shared library** used by the `trace_cuda` gadget to instrument CUDA kernel launches.

The purpose of this library is to:

* Subscribe to **CUPTI Runtime and Driver API callbacks**
* Capture CUDA kernel launch events
* Correlate runtime and driver API calls using CUPTI correlation IDs
* Emit **USDT (User Statically Defined Tracing) probes**
* Provide structured kernel launch data to the eBPF layer

This library acts as the bridge between:

```
CUDA application
        ↓
     CUPTI
        ↓
  USDT probes
        ↓
   eBPF gadget
```


## Why This Library Exists

CUPTI operates inside the target process and provides access to:

* CUDA Runtime API callbacks
* CUDA Driver API callbacks
* Correlation IDs
* Kernel symbol names
* Launch results

The library exports USDT probes that allow the `trace_cuda` and `cuda_metrics` eBPF gadget to attach and collect kernel launch information without modifying the CUDA application itself.


## Current Build System

For now, the library is built using **CMake**.


## Build Instructions

From inside the `trace_cuda/cupti` directory:

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

This will produce a shared library:

```
libtrace_cuda_cupti.so
```
### Install (Recommended)

To install the library into the default system location (`/usr/local/lib`):

```bash
sudo cmake --install build
sudo ldconfig
```

`ldconfig` updates the dynamic linker cache so the system can discover the library when linking by name.

After installation, you can verify:

```bash
ldconfig -p | grep trace_cuda
```

You should see:

```
libtrace_cuda_cupti.so => /usr/local/lib/libtrace_cuda_cupti.so
```

## Runtime Usage
The shared library is injected using CUDA’s built-in injection mechanism via the `CUDA_INJECTION64_PATH` environment variable.
Example:
```
export CUDA_INJECTION64_PATH=/usr/local/lib/libtrace_cuda_cupti.so
```
Then run your CUDA application normally

