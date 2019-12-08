# Builder: traceloop

FROM docker.io/kinvolk/traceloop:latest as traceloop

# Builder: bpftool

FROM docker.io/kinvolk/bpftool:20191122204402789b1a as bpftool-build

# Builder: cgroupid

FROM kinvolk/cgroupid as cgroupid

# Main gadget image

FROM docker.io/kinvolk/bcc:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates curl && \
	curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && \
	chmod +x kubectl && \
	mv kubectl /bin/

COPY files/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY files/runc-hook-prestart-create-maps.sh /bin/runc-hook-prestart-create-maps.sh
COPY files/entrypoint.sh /entrypoint.sh
COPY files/bcck8s /opt/bcck8s

COPY bin/gadgettracermanager /bin/gadgettracermanager

COPY --from=bpftool-build /bin/bpftool /bin/bpftool
COPY --from=traceloop /bin/traceloop /bin/traceloop
COPY --from=cgroupid /bin/cgroupid /bin/cgroupid

