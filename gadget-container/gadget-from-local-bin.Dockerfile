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
		ca-certificates curl && \
        rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY entrypoint.sh /entrypoint.sh
COPY cleanup.sh /cleanup.sh

COPY bin/gadgettracermanager /bin/gadgettracermanager
COPY gadgets/bcck8s /opt/bcck8s

COPY bin/networkpolicyadvisor /bin/networkpolicyadvisor

COPY bin/traceloop /bin/traceloop

## Hooks Begins

# OCI
COPY hooks/oci/prestart.sh /opt/hooks/oci/prestart.sh
COPY hooks/oci/poststop.sh /opt/hooks/oci/poststop.sh
COPY bin/ocihookgadget /opt/hooks/oci/ocihookgadget

# runc
COPY bin/runchooks.so /opt/hooks/runc/runchooks.so
COPY hooks/runc/add-hooks.jq /opt/hooks/runc/add-hooks.jq

# cri-o
COPY hooks/crio/gadget-prestart.json /opt/hooks/crio/gadget-prestart.json
COPY hooks/crio/gadget-poststop.json /opt/hooks/crio/gadget-poststop.json

## Hooks Ends
