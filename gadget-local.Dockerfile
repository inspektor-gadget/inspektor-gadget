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
		ca-certificates curl jq && \
        rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY gadget-container/bin/gadgettracermanager /bin/
COPY gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/bcck8s/

COPY gadget-container/bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY gadget-container/bin/ocihookgadget /opt/hooks/oci/

# runc
COPY gadget-container/bin/runchooks.so /opt/hooks/runc/
COPY gadget-container/hooks/runc/add-hooks.jq /opt/hooks/runc/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends
