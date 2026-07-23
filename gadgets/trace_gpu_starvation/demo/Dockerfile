# Container image for the trace_gpu_starvation / profile_cpu --gpu-idle-only demo
# workload (gadgets/trace_gpu_starvation/demo/video_frame_inference.py).
#
# Build and push to your registry, e.g.:
#   docker build -t $CONTAINER_REPO/workload/gpu-starvation-demo:latest \
#       gadgets/trace_gpu_starvation/demo
#   docker push $CONTAINER_REPO/workload/gpu-starvation-demo:latest
#
# The base image already ships torch + CUDA runtime; we add torchvision (for
# resnet50), numpy and a headless OpenCV (no GUI/GL libraries needed).
FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime

# opencv-python-headless avoids libGL/X11 dependencies. numpy is pulled in by
# torch already, but pin it explicitly so the demo's imports are self-contained.
RUN pip install --no-cache-dir \
        torchvision==0.20.1 \
        opencv-python-headless \
        numpy

WORKDIR /demo
COPY video_frame_inference.py .

# Default: sequential (GPU-starving) mode, looping forever so the gadget has
# time to observe it. Override the mode by changing the last arg (bad/good/
# threaded) and the number of frames via the N_FRAMES env var (0 = forever).
ENV N_FRAMES=0
ENTRYPOINT ["python", "video_frame_inference.py"]
CMD ["bad"]
