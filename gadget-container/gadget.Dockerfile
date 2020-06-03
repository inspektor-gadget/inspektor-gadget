# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/0b9f44a1b61b528145f56c8e4b271186be6028f2
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:202005220209060b9f44 as traceloop

# Main gadget image

# BCC built from:
# https://github.com/kinvolk/bcc/commit/5fed2a94da19501c3088161db0c412b5623050ca
# See:
# - https://github.com/kinvolk/bcc/actions
# - https://hub.docker.com/r/kinvolk/bcc/tags

FROM docker.io/kinvolk/bcc:202006031708335fed2a

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

COPY bin/runchooks.so /opt/runchooks/runchooks.so
COPY runchooks/add-hooks.jq /opt/runchooks/add-hooks.jq

COPY crio-hooks/gadget-prestart.json /opt/crio-hooks/gadget-prestart.json
COPY crio-hooks/gadget-poststop.json /opt/crio-hooks/gadget-poststop.json

COPY --from=traceloop /bin/traceloop /bin/traceloop
