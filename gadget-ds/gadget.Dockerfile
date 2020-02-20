# Builder: traceloop

FROM docker.io/kinvolk/traceloop:latest as traceloop

# Main gadget image

FROM docker.io/kinvolk/bcc:ig-latest
RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl

COPY files/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY files/runc-hook-poststop.sh /bin/runc-hook-poststop.sh
COPY files/entrypoint.sh /entrypoint.sh
COPY files/bcck8s /opt/bcck8s

COPY bin/gadgettracermanager /bin/gadgettracermanager
COPY bin/ocihookgadget /bin/ocihookgadget
COPY bin/networkpolicyadvisor /bin/networkpolicyadvisor

COPY --from=traceloop /bin/traceloop /bin/traceloop

