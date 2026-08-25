#!/usr/bin/python3
#
# CPU-bound pure-Python workload for the profile_cpu OTel eBPF profiler test.
#
# profile_cpu is a perf_event gadget. To validate OTel/Python stack
# symbolization from a perf_event program, we need a process that keeps the
# CPython interpreter busy in recognizable Python frames so that the
# perf_event sampler can repeatedly land in them and the OTel eBPF profiler
# can symbolize them (compute_fibonacci / burn_cpu / main).

import sys
import time


def compute_fibonacci(n):
    if n < 2:
        return n
    return compute_fibonacci(n - 1) + compute_fibonacci(n - 2)


def burn_cpu(deadline):
    total = 0
    while time.time() < deadline:
        total += compute_fibonacci(20)
    return total


def main():
    # The test waits for the OTel eBPF profiler to initialize before starting
    # this workload. Keep running long enough for the profiler to analyze this
    # process and collect symbolized samples.
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    burn_cpu(time.time() + duration)


if __name__ == "__main__":
    main()
