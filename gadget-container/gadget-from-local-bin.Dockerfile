# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/ba3f5a
# See:
# - https://github.com/kinvolk/bcc/actions
# - https://hub.docker.com/r/kinvolk/bcc/tags

FROM docker.io/kinvolk/bcc:20200608131331ba3f5a

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl && \
        rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY entrypoint.sh /entrypoint.sh
COPY cleanup.sh /cleanup.sh

COPY ocihookgadget/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY ocihookgadget/runc-hook-poststop.sh /bin/runc-hook-poststop.sh
COPY bin/ocihookgadget /bin/ocihookgadget

COPY bin/gadgettracermanager /bin/gadgettracermanager

COPY gadgets/bcck8s /opt/bcck8s
COPY bin/networkpolicyadvisor /bin/networkpolicyadvisor

COPY bin/runchooks.so /opt/runchooks/runchooks.so
COPY runchooks/add-hooks.jq /opt/runchooks/add-hooks.jq

COPY crio-hooks/gadget-prestart.json /opt/crio-hooks/gadget-prestart.json
COPY crio-hooks/gadget-poststop.json /opt/crio-hooks/gadget-poststop.json

COPY bin/traceloop /bin/traceloop
