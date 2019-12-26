# Builder: traceloop

FROM docker.io/kinvolk/traceloop:latest as traceloop

# Main gadget image

FROM docker.io/kinvolk/bcc:ig-latest

COPY files/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY files/runc-hook-poststop.sh /bin/runc-hook-poststop.sh
COPY files/entrypoint.sh /entrypoint.sh
COPY files/bcck8s /opt/bcck8s
COPY files/ocihookotel /bin/

COPY out/gadgettracermanager /bin/gadgettracermanager
COPY out/ocihookgadget /bin/ocihookgadget
COPY out/*.py /opt/bcck8s/
COPY out/runchooks.so /opt/
COPY out/container-ldpreload.so /opt/
COPY out/otel.tar.gz /opt/

COPY --from=traceloop /bin/traceloop /bin/traceloop

