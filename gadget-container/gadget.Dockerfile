# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/b02325929a835060df5cf82e37389edf87421a39
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/repository/docker/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:20200511163751b02325 as traceloop

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
