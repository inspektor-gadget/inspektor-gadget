# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/a4887a9514f3cd7f38b714670a4e031cc2d1031d
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/repository/docker/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:20200514020844a4887a as traceloop

# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/ab54de2e4449027f2b4dccd022adc57bec4fd4eb
# See:
# - https://github.com/kinvolk/bcc/actions
# - https://hub.docker.com/repository/docker/kinvolk/bcc/tags

FROM docker.io/kinvolk/bcc:20200330122541ab54de

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl

COPY entrypoint.sh /entrypoint.sh
COPY cleanup.sh /cleanup.sh

COPY ocihookgadget/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY ocihookgadget/runc-hook-poststop.sh /bin/runc-hook-poststop.sh
COPY bin/ocihookgadget /bin/ocihookgadget

COPY bin/gadgettracermanager /bin/gadgettracermanager

COPY gadgets/bcck8s /opt/bcck8s
COPY bin/networkpolicyadvisor /bin/networkpolicyadvisor

COPY --from=traceloop /bin/traceloop /bin/traceloop
