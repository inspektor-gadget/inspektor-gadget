---
title: 'Kubernetes CLI Options'
sidebar_position: 700
description: Advanced CLI options for kubectl gadget
---

## Kubernetes CLI Runtime options

The Inspektor Gadget `kubectl` plugin uses the [kubernetes
cli-runtime](https://github.com/kubernetes/cli-runtime) helpers. This adds
support for many CLI options that are common to many Kubernetes tools,
which let us specify how to connect to the cluster, which kubeconfig to
use, and so on.

```bash
  --as string                      Username to impersonate for the operation
  --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
  --cache-dir string               Default cache directory (default "/home/marga/.kube/cache")
  --certificate-authority string   Path to a cert file for the certificate authority
  --client-certificate string      Path to a client certificate file for TLS
  --client-key string              Path to a client key file for TLS
  --cluster string                 The name of the kubeconfig cluster to use
  --context string                 The name of the kubeconfig context to use
  --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
  --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
, --server string                  The address and port of the Kubernetes API server
  --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
  --token string                   Bearer token for authentication to the API server
  --user string                    The name of the kubeconfig user to use
```

If none of these options are specified, Inspektor Gadget will connect to the
cluster configured in the default kubeconfig location, with the default
connection options.
