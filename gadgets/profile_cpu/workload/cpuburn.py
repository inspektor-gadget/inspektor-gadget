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
    # Default duration is generous: the OTel eBPF profiler needs ~16s to
    # initialize and a few more seconds to analyze this process before it can
    # symbolize its Python frames. The test starts the gadget, waits for the
    # profiler to initialize, then runs this workload.
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    burn_cpu(time.time() + duration)


if __name__ == "__main__":
    main()
