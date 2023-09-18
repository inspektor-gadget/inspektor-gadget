---
title: 'Common Features'
weight: 10
description: 'An overview of the common features shared across gadgets'
---

Inspektor Gadget comes with a wide array of gadgets that allow us to
inspect what's going on in our clusters. The flags and parameters that we
can pass to each specific gadget may differ, but there are some that are
supported across all gadgets.

## Event Filtering

There are several ways to choose the pods or containers that we want to
trace:

 * `--node string`, show only data from pods running in that node
 * `-n string`, `--namespace string`, show data from pods in that namespace
 * `-A`, `--all-namespaces`, show data from pods in all namespaces
 * `-p string`, `--podname string`, show only data from pods with that name
 * `-c string`, `--containername string`, show only data from containers with that name
 * `-l string`, `--selector string`: show only data that matches the given
   label or selector. Only `=` is currently supported (e.g. `key1=value1,key2=value2`).

We can use one or more of these parameters to choose which pods or
containers will be inspected by our gadgets.

For example:

```bash
$ kubectl gadget trace exec -n demo -l app=myapp
```

Will run the `exec` tracer for all pods in the `demo` namespace that have
the `app=myapp` label.

```bash
$ kubectl gadget snapshot socket -A -p nginx
```

Will get the `socket` snapshot for all pods with name `nginx`, regardless
of which namespace they are in.

## Output Format

The `-o` or `--output` flag lets us decide the format for the output the
gadget will generate. The default `columns` output shows some of the
information gathered, arranged in text columns on the console.

This can be overridden with:
- `json`
- `jsonpretty`
- `yaml`
- `columns`

### JSON Output

Passing `-o json` will print all the information gathered in JSON format.
Each entry is printed on a single line, so the output can be easily parsed line by line.

For example:
```bash
$ kubectl gadget trace tcp -A -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "kube-system",
  "pod": "coredns-66bff467f8-8ftjm",
  "container": "coredns",
  "pid": 2688,
  "comm": "coredns",
  "ipversion": 4,
  "saddr": "127.0.0.1",
  "daddr": "127.0.0.1",
  "sport": 46010,
  "dport": 8080,
  "operation": "connect"
}
```

### JSON Pretty Output

Passing `-o jsonpretty` will print all the information gathered in JSON format but with indentation making it easier to read.

### YAML Output

Passing `-o yaml` will print all the information gathered in YAML format.
Each entry is preceded by the end of directives markers (`---`).

### Custom Columns

Using `-o columns=column1,column2` we can choose which columns to
print. We can use the JSON output to know the names of all the available
columns for a given gadget.

For example, when tracing which processes were killed because of the node
running out of memory, we can choose to only print the PID and command of
the killed process:

```bash
$ kubectl gadget trace oomkill -A -o columns=kpid,kcomm
KPID   KCOMM
15182  tail
```

## Run for a specific amount of time

Many gadgets will run forever, printing the gathered output until we press
Ctrl-C to stop them. If we want to run a gadget only for a window of time,
we can use the `--timeout int` flag, passing the number of seconds during which
we want to run the gadget.

For example, we can trace files that get opened by pods in the `gadget`
namespace during a window of 5 seconds, like this:

```bash
$ kubectl gadget trace open -n gadget --timeout 5
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             FD    ERR PATH
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  3     0   /etc/ld.so.cache
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  3     0   /lib/x86_64-linux-gnu/libpthread.so.0
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  3     0   /lib/x86_64-linux-gnu/libseccomp.so.2
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  3     0   /lib/x86_64-linux-gnu/libc.so.6
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  3     0   /sys/kernel/mm/transparent_hugepage/hpage_pmd_size
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  6     0   /usr/bin/gadgettracermanager
minikube         gadget           gadget-vhcj7     gadget           1303299 gadgettracerman  6     0   /etc/localtime
```

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
