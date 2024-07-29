# trace ssl

Captures data on read/recv or write/send functions of OpenSSL, GnuTLS, NSS and Libcrypto

## Getting started
Pulling the gadget:
```
sudo ig image pull ghcr.io/inspektor-gadget/gadget/trace_ssl:latest
```
Running the gadget:
```
sudo ig run ghcr.io/inspektor-gadget/gadget/trace_ssl:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_ssl:latest [flags]
```

## Flags

### `--record-data`
controls whether the gadget will send data to userspace

Default value: "true"
