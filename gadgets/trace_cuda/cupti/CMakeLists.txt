cmake_minimum_required(VERSION 3.18)
project(cupti_sandbox LANGUAGES C CXX )

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Default to Debug if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

find_package(CUDAToolkit REQUIRED)

add_library(trace_cuda_cupti SHARED
  cupti_tracer.c
  correlation.cpp
)

target_link_libraries(trace_cuda_cupti PRIVATE
    CUDA::cudart
    CUDA::cuda_driver
    CUDA::cupti
    dl
)

install(TARGETS trace_cuda_cupti
        EXPORT trace_cuda_cuptiTargets
        LIBRARY DESTINATION lib)

install(EXPORT trace_cuda_cuptiTargets
        FILE trace_cuda_cuptiTargets.cmake
        NAMESPACE trace_cuda_cupti::
        DESTINATION lib/cmake/trace_cuda_cupti)
