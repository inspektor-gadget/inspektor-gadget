#!/usr/bin/env python3
"""
GPU starvation demo: frame-by-frame video inference.

Usage:
  python video_frame_inference.py bad       # sequential (GPU starves)
  python video_frame_inference.py good      # pipelined (GPU + CPU overlap)
  python video_frame_inference.py threaded  # bad, 2-thread version

All modes print a periodic timing report (windowed average of per-frame CPU
preprocessing time and GPU inference time) so the stall-duration assumptions
can be validated. Environment variables:
  N_FRAMES      number of frames to process (0 = loop forever; default 60)
  REPORT_EVERY  print the timing report every N frames (0 = only final; default 5)
  PREPROCESS_MS deterministic CPU-preprocess time per frame in ms (default 1500).
                The real cv2.resize/normalize work is repeated until this budget
                is spent, so the GPU-idle stall is the same on any CPU instead of
                depending on how fast the node happens to be.
  INFER_MS      target GPU-inference time per frame in ms (default 1500). The
                model is run a calibrated number of times so the GPU stays busy
                about as long as the CPU preprocesses. Keeping INFER_MS >=
                PREPROCESS_MS is what lets the pipelined 'good' mode hide the CPU
                work and NOT starve the GPU; with a trivial (few-ms) GPU load the
                GPU would drain in 'good' too and both modes would look starved.
  BATCH         inference batch size (default 64). Larger batches produce
                longer, high-occupancy GPU kernels that NVML per-process
                utilization sampling can actually observe; with BATCH=1 the
                kernels are too small for NVML to register, so even a genuinely
                GPU-busy 'good' run looks idle to the gadget.

Requires: torch, torchvision, numpy, opencv-python (cv2)
A GPU is NOT required: in no-GPU mode, replace .cuda() with .cpu()
and the demo still shows the scheduling pattern.
"""
import sys
import time
import threading
import queue
import os
import itertools

import cv2
import numpy as np
import torch
import torchvision.models as models

FRAME_W, FRAME_H = 1920, 1080      # Full HD — makes CPU work realistically heavy
# Inference batch size. This is critical for the demo to be *observable*, not
# just correct: the gadget relies on NVML per-process GPU-utilization sampling,
# which does not register short, low-occupancy kernels. A batch=1 resnet50
# forward barely touches the SMs (~9% device util) and NVML reports the process
# as idle even while it is busy, so the pipelined 'good' run looks starved to
# the gadget. A larger batch produces longer, high-occupancy kernels that NVML
# actually samples as active, so 'good' is correctly seen as GPU-busy.
BATCH = int(os.environ.get("BATCH", "64"))
# Number of frames to process. Overridable via the N_FRAMES env var so the
# containerized demo can run long enough to be observed (0 = loop forever).
N_FRAMES = int(os.environ.get("N_FRAMES", "60"))
# How often (in frames) to print the running CPU/GPU timing report. Set to 0
# to disable periodic reports (only the final summary is printed). Frames now
# take ~PREPROCESS_MS + INFER_MS each, so a small window keeps reports frequent.
REPORT_EVERY = int(os.environ.get("REPORT_EVERY", "5"))
INPUT_SIZE = 224
# Deterministic per-frame CPU-preprocess and GPU-infer budgets (ms). The demo
# must not depend on how fast the CPU/GPU happen to be, so we repeat real work
# until these wall-clock budgets are spent. INFER_MS >= PREPROCESS_MS keeps the
# GPU busy at least as long as the CPU preps: 'good' (pipelined) hides the CPU
# work behind GPU work, while 'bad' (sequential) leaves the GPU idle for
# ~PREPROCESS_MS every frame.
PREPROCESS_MS = int(os.environ.get("PREPROCESS_MS", "1500"))
INFER_MS = int(os.environ.get("INFER_MS", "1500"))
# ImageNet normalization constants, hoisted to module scope so the
# cpu_preprocess() time-loop doesn't rebuild them on every iteration.
_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)
# Number of model invocations per frame needed to reach ~INFER_MS; calibrated
# at startup once the device is known (see calibrate_gpu_iters).
GPU_ITERS = 1

model = models.resnet50(weights=None)
device = "cuda" if torch.cuda.is_available() else "cpu"
model = model.to(device).eval()

# ── helpers ──────────────────────────────────────────────────────────────────

def frame_range(n):
    """range(n), or an endless counter when n == 0 (containerized demo)."""
    return itertools.count() if n == 0 else range(n)

class Stats:
    """Accumulates per-frame CPU-preprocess and GPU-infer times and prints a
    windowed running average, so timing can be validated even when the demo
    loops forever (N_FRAMES=0). Call add() per frame and report() at the end."""

    def __init__(self, label, overlap=False):
        self.label = label
        # When overlap is True (pipelined 'good' mode) GPU work runs
        # concurrently with the next frame's CPU prep, so the real GPU-idle
        # time is max(0, cpu - gpu), not cpu.
        self.overlap = overlap
        self.n = 0
        self._cpu_ms = []
        self._gpu_ms = []

    def add(self, cpu_ms, gpu_ms):
        self.n += 1
        self._cpu_ms.append(cpu_ms)
        self._gpu_ms.append(gpu_ms)
        if REPORT_EVERY and self.n % REPORT_EVERY == 0:
            self.report()

    def report(self):
        if not self._cpu_ms:
            return
        cpu = sum(self._cpu_ms) / len(self._cpu_ms)
        gpu = sum(self._gpu_ms) / len(self._gpu_ms)
        idle = max(0.0, cpu - gpu) if self.overlap else cpu
        window = len(self._cpu_ms)
        print(f"  [{self.label}] frame {self.n} "
              f"(avg over last {window}): "
              f"CPU preprocess {cpu:.1f}ms | GPU infer {gpu:.1f}ms | "
              f"GPU idle ~{idle:.0f}ms/frame", flush=True)
        # Windowed average: drop the samples we just reported.
        self._cpu_ms.clear()
        self._gpu_ms.clear()

def gpu_events():
    """A (start, end) CUDA event pair for accurate GPU timing, or (None, None)
    when running CPU-only."""
    if device == "cuda":
        return (torch.cuda.Event(enable_timing=True),
                torch.cuda.Event(enable_timing=True))
    return None, None

def gpu_elapsed_ms(start_ev, end_ev, wall_start):
    """Elapsed GPU time in ms: CUDA-event based on GPU, wall-clock fallback
    otherwise. wall_start is a time.perf_counter() taken before the CPU-only
    run so the fallback can measure it."""
    if device == "cuda":
        return start_ev.elapsed_time(end_ev)
    return (time.perf_counter() - wall_start) * 1000

def fake_decode():
    """Simulate decoding one frame from a video stream."""
    return np.random.randint(0, 256, (FRAME_H, FRAME_W, 3), dtype=np.uint8)

def _preprocess_once(frame: np.ndarray) -> np.ndarray:
    """One realistic preprocessing pass: resize + BGR→RGB + float normalize.
    The hot frames are cv2.resize / numpy, which is what the gadget attributes."""
    small = cv2.resize(frame, (INPUT_SIZE, INPUT_SIZE),
                       interpolation=cv2.INTER_LANCZOS4)
    rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    return ((rgb - _MEAN) / _STD).transpose(2, 0, 1)   # CHW

def cpu_preprocess(frame: np.ndarray) -> np.ndarray:
    """
    Heavy CPU preprocessing: repeat the real resize + color-convert + normalize
    work until PREPROCESS_MS of wall-clock has elapsed, then return the last
    result. Repeating a fixed-cost operation (rather than assuming one pass is
    slow) makes the GPU-idle stall deterministic on any CPU, while keeping the
    on-CPU stack on cv2.resize / numpy — exactly the code path the gadget blames.
    """
    deadline = time.perf_counter() + PREPROCESS_MS / 1000.0
    while True:
        out = _preprocess_once(frame)
        if time.perf_counter() >= deadline:
            return out

def to_tensor(arr: np.ndarray) -> torch.Tensor:
    """Turn one preprocessed CHW frame into a BATCH-sized input tensor. The
    frame is replicated across the batch dimension so each model() call is a
    realistic, high-occupancy GPU workload (see BATCH for why this matters)."""
    t = torch.from_numpy(arr).unsqueeze(0).to(device)
    return t.repeat(BATCH, 1, 1, 1) if BATCH > 1 else t

def stage_into(static_input: torch.Tensor, arr: np.ndarray) -> None:
    """Copy a preprocessed CHW frame into the CUDA graph's static input buffer,
    in place, so the next graph.replay() runs on the latest frame without
    re-capturing. The buffer address is fixed (captured by the graph); copy_
    preserves it."""
    t = torch.from_numpy(arr).unsqueeze(0)
    if BATCH > 1:
        t = t.repeat(BATCH, 1, 1, 1)
    static_input.copy_(t.to(device))

def calibrate_gpu_iters() -> int:
    """Measure a single model() call and return how many calls approximate
    INFER_MS, so the GPU stays busy ~INFER_MS per frame on this hardware.
    Returns 1 when running CPU-only (no meaningful GPU timing)."""
    if device != "cuda":
        return 1
    sample = to_tensor(_preprocess_once(fake_decode()))
    with torch.no_grad():
        for _ in range(3):            # warm up cuDNN autotuning
            _ = model(sample)
    torch.cuda.synchronize()
    probes = 10
    t0 = time.perf_counter()
    with torch.no_grad():
        for _ in range(probes):
            _ = model(sample)
    torch.cuda.synchronize()
    single_ms = (time.perf_counter() - t0) * 1000 / probes
    iters = max(1, round(INFER_MS / single_ms))
    print(f"[calib] single infer {single_ms:.2f}ms -> {iters} iters/frame "
          f"(~{single_ms * iters:.0f}ms GPU/frame, target {INFER_MS}ms)",
          flush=True)
    return iters

def gpu_infer(tensor):
    """Run the model GPU_ITERS times so the GPU is busy ~INFER_MS per frame.
    Used by the sequential 'bad' modes: the many eager kernel launches keep the
    CPU busy driving the GPU, so preprocessing cannot overlap. The pipelined
    'good' mode instead replays a captured CUDA graph (see good_pipelined)."""
    with torch.no_grad():
        for _ in range(GPU_ITERS):
            _ = model(tensor)

# ── bad: sequential ───────────────────────────────────────────────────────────

def bad_sequential(n=N_FRAMES):
    """
    Anti-pattern: CPU preprocessing blocks next GPU kernel launch.
    The GPU sits idle while the CPU preprocesses each frame.
    trace_gpu_starvation will fire here: stack points at cv2.resize / numpy.

    Prints per-frame timing so we can verify the stall duration matches
    expectations: GPU idle should be ~PREPROCESS_MS (default 1500ms), well above
    the gadget's default --min-idle-ms of 1000ms.
    """
    print("[BAD] Sequential: CPU preprocess → GPU infer, one frame at a time")
    stats = Stats("bad")
    for i in frame_range(n):
        raw = fake_decode()

        # === GPU is IDLE here — this is what the gadget detects ===
        t0 = time.perf_counter()
        arr = cpu_preprocess(raw)
        cpu_ms = (time.perf_counter() - t0) * 1000
        # ===========================================================

        tensor = to_tensor(arr)
        start_ev, end_ev = gpu_events()
        gpu_wall = time.perf_counter()
        if device == "cuda":
            start_ev.record()
        gpu_infer(tensor)
        if device == "cuda":
            end_ev.record()
            torch.cuda.synchronize()
        gpu_ms = gpu_elapsed_ms(start_ev, end_ev, gpu_wall)

        stats.add(cpu_ms, gpu_ms)
    stats.report()

# ── bad: two-thread version (scenario 2) ─────────────────────────────────────

def bad_threaded(n=N_FRAMES):
    """
    Anti-pattern: inference thread (which holds GPU memory) blocks on a queue
    while the prep thread does CPU work. Two distinct stacks appear:
      - inference thread: futex_wait / queue.get  (blocking)
      - prep thread:      cv2.resize / numpy       (actual bottleneck)
    """
    print("[BAD] Threaded: prep thread feeds inference thread via queue")
    stats = Stats("threaded")
    q = queue.Queue(maxsize=2)

    def prep_worker():
        for _ in frame_range(n):
            # Time the CPU preprocessing in the prep thread and hand the
            # measurement to the consumer alongside the tensor.
            t0 = time.perf_counter()
            arr = cpu_preprocess(fake_decode())
            cpu_ms = (time.perf_counter() - t0) * 1000
            q.put((arr, cpu_ms))
        q.put(None)

    t = threading.Thread(target=prep_worker, daemon=True)
    t.start()

    while True:
        item = q.get()    # ← inference thread blocks here (futex)
        if item is None:
            break
        arr, cpu_ms = item
        tensor = to_tensor(arr)
        start_ev, end_ev = gpu_events()
        gpu_wall = time.perf_counter()
        if device == "cuda":
            start_ev.record()
        gpu_infer(tensor)
        if device == "cuda":
            end_ev.record()
            torch.cuda.synchronize()
        gpu_ms = gpu_elapsed_ms(start_ev, end_ev, gpu_wall)
        stats.add(cpu_ms, gpu_ms)
    t.join()
    stats.report()

# ── good: pipelined ───────────────────────────────────────────────────────────

def good_pipelined(n=N_FRAMES):
    """
    Best practice: GPU processes frame N while CPU preprocesses frame N+1.

    Overlap is achieved with a CUDA graph. Capturing one forward pass and
    replaying it GPU_ITERS times issues GPU_ITERS *single* lightweight launches
    that enqueue in ~ms and return to the CPU, so the GPU runs ~INFER_MS
    asynchronously while the CPU preprocesses the next frame. (Issuing the same
    work eagerly -- GPU_ITERS x ~50 kernels per resnet50 forward -- overflows
    CUDA's launch queue, blocking the calling thread for the whole GPU compute
    and serializing the pipeline, which is exactly what 'bad' does.)

    trace_gpu_starvation should NOT fire: the GPU stays busy while the CPU preps.
    """
    print("[GOOD] Pipelined: GPU and CPU overlap via CUDA graph replay")
    if device != "cuda":
        print("  (no CUDA — running CPU-only pipeline; overlap not demonstrated)")
        bad_sequential(n)
        return

    stats = Stats("good", overlap=True)

    # Static input buffer the graph captures; each new frame is copied into it.
    static_input = to_tensor(cpu_preprocess(fake_decode()))

    # Warm up cuDNN algorithm selection for this shape on a side stream, then
    # capture a single forward pass. Capturing one forward (not GPU_ITERS) keeps
    # the graph's private memory pool to one forward's activations, so a large
    # BATCH does not multiply memory by GPU_ITERS.
    warm = torch.cuda.Stream()
    warm.wait_stream(torch.cuda.current_stream())
    with torch.cuda.stream(warm), torch.no_grad():
        for _ in range(3):
            _ = model(static_input)
    torch.cuda.current_stream().wait_stream(warm)
    torch.cuda.synchronize()

    graph = torch.cuda.CUDAGraph()
    with torch.no_grad(), torch.cuda.graph(graph):
        _ = model(static_input)

    for _ in frame_range(n):
        start_ev, end_ev = gpu_events()
        start_ev.record()
        # GPU_ITERS single-launch replays: enqueue near-instantly, run ~INFER_MS
        # on the GPU asynchronously.
        for _ in range(GPU_ITERS):
            graph.replay()
        end_ev.record()

        # CPU preps the NEXT frame while the GPU replays (real overlap).
        t0 = time.perf_counter()
        nxt = cpu_preprocess(fake_decode())
        cpu_ms = (time.perf_counter() - t0) * 1000

        torch.cuda.synchronize()
        gpu_ms = start_ev.elapsed_time(end_ev)
        stats.add(cpu_ms, gpu_ms)

        # Stage the next frame into the captured input buffer for the next replay.
        stage_into(static_input, nxt)
    stats.report()

# ── main ──────────────────────────────────────────────────────────────────────

MODES = {"bad": bad_sequential, "good": good_pipelined, "threaded": bad_threaded}

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "bad"
    if mode not in MODES:
        print(f"Usage: {sys.argv[0]} {'|'.join(MODES)}")
        sys.exit(1)
    t0 = time.time()
    GPU_ITERS = calibrate_gpu_iters()
    print(f"[config] device={device} BATCH={BATCH} PREPROCESS_MS={PREPROCESS_MS} "
          f"INFER_MS={INFER_MS} GPU_ITERS={GPU_ITERS}", flush=True)
    MODES[mode]()
    print(f"Done in {time.time()-t0:.1f}s")
