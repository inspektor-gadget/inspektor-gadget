# Builder: traceloop

FROM docker.io/kinvolk/traceloop:latest as traceloop

# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/e44b7667f69a12fa52812ecf3d1ed19d4db4cdad
# See:
# - https://github.com/kinvolk/bcc/actions
# - https://hub.docker.com/repository/docker/kinvolk/bcc/tags

FROM docker.io/kinvolk/bcc:20200322162936e44b76

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

COPY bin/runchooks.so /opt/runchooks/runchooks.so
COPY bin/add-hooks.jq /opt/runchooks/add-hooks.jq

COPY --from=traceloop /bin/traceloop /bin/traceloop

