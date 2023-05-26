---
title: 'Using prometheus'
weight: 30
description: >
  Expose metrics using prometheus
---

The Prometheus gadget collects and exposes metrics in Prometheus format. It's available in both, for
Kubernetes (`ig-k8s`) and in Linux hosts (`ig`).


```bash
$ kubectl gadget prometheus --config @<path>
$ ig prometheus --config @<path> --metrics-listen-address $IP:$PORT --metrics-path /metrics
```

## Configuration File

The configuration files defines the metrics to be exposed and their settings. The structure of this
file is:

```yaml
metrics:
  - name: metric_name
    type: counter, gauge or histogram
    category: foo # category of the gadget to collect the metric. trace, snapshot, etc.
    gadget: bar # gadget used to collect the metric. exec, open, etc.
    selector:
      # defines which events to take into consideration when updating the metrics.
      # See more information below.
    labels:
      # defines the granularity of the labels to capture. See below.
```

### Filtering (aka Selectors)

It's possible to configure Inspektor Gadget to only update metrics for some specific labels. This is
useful to keep the cardinality of the labels low.

```yaml
  selector:
  - "columnName:value" # matches if the content of the column is equals to value
  - "columnName:!value" # matches if the content of the column is not equal to value
  - "columnName:>=value" # matches if the content of the column is greater and equal to value
  - "columnName:>value" # matches if the content of columnName is greater than the value
  - "columnName:<=value" # matches, if the content of columnName is lower or equal to the value
  - "columnName:<value" # matches, if the content of columnName is lower than the value
  - "columnName:~value" # matches if the content of column matches the regular expression 'value'.
                        # see https://github.com/google/re2/wiki/Syntax for more information on the syntax.
```

Some examples are:

Only metrics for default namespace

```yaml
selector:
  - namespace: default
```

Only events with retval != 0

```yaml
selector:
  - "retval:!0"
```

Only events executed by pid 1 by non root users

```yaml
selector:
  - "pid:0"
  - "uid:>=1"
```

### Counters

This is the most intuitive metric: "A _counter_ is a cumulative metric that represents a
single [monotonically increasing counter](https://en.wikipedia.org/wiki/Monotonic_function) whose
value can only increase or be reset to zero on restart. For example, you can use a counter to
represent the number of requests served, tasks completed, or errors." from
[https://prometheus.io/docs/concepts/metric_types/#counter](https://prometheus.io/docs/concepts/metric_types/#counter).

The following are examples of counters we can support with the existing gadgets. The first one
counts the number of executed processes by namespace, pod and container.

```yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
```

By default, a counter is increased by one each time there is an event, however it's possible to
increase a counter using a field on the event too.

Executed processes by pod and container in the default namespace

```yaml
- name: executed_processes
  type: counter
  category: trace
  gadget: exec
  labels:
    - pod
    - container
  selector:
    - "namespace:default"
```

Or only count events for a given command:

`cat` executions by namespace, pod and container

```yaml
- name: executed_cats # ohno!
  type: counter
  category: trace
  gadget: exec
  labels:
    - namespace
    - pod
    - container
  selector:
    - "comm:cat"
```

DNS requests aggregated by namespace and pod

```yaml
- name: dns_requests
  type: counter
  category: trace
  gadget: dns
  labels:
    - namespace
    - pod
  selector:
    - "qr:Q" # Only count query events
```

### Gauges

"A _gauge_ is a metric that represents a single numerical value that can arbitrarily go up and down"
from
[https://prometheus.io/docs/concepts/metric_types/#gauge](https://prometheus.io/docs/concepts/metric_types/#gauge).

Right now only snapshotters are supported.

Examples of gauges are:

Number of processes by namespace, pod and container.

```yaml
- name: number_of_processes
  type: gauge
  category: snapshot
  gadget: process
  labels:
    - namespace
    - pod
    - container
```

Number of sockets in `CLOSE_WAIT` state

```yaml
- name: number_of_sockets_close_wait
  type: gauge
  category: snapshot
  gadget: socket
  labels:
    - namespace
    - pod
    - container
  selector:
    - "status:CLOSE_WAIT"
```

### Guide

Let's see how we can use this gadget in different environments.

#### On kubernetes

In this guide we'll use the Prometheus Service Discovery: it automatically detects the endpoints to
scrape metrics from.

If you already have a Prometheus instance running in your cluster, be sure you provide it with the
following configuration:

```yaml
scrape_configs:
  - job_name: 'kubernetes-pods'

    scrape_interval: 1s
    scrape_timeout: 1s

    kubernetes_sd_configs:
    - role: pod

    relabel_configs:
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
      action: keep
      regex: true
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scheme]
      action: replace
      target_label: __scheme__
      regex: (https?)
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
      action: replace
      target_label: __metrics_path__
      regex: (.+)
    - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
      action: replace
      target_label: __address__
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:$2
```

Otherwise, you can just apply the config provided with this guide:

```bash
$ kubectl apply -f prometheus.yaml
namespace/monitoring created
serviceaccount/prometheus created
clusterrole.rbac.authorization.k8s.io/discoverer created
clusterrolebinding.rbac.authorization.k8s.io/prometheus-discoverer created
configmap/prometheus-server-conf created
deployment.apps/prometheus created
```

Create a port-forward session to Prometheus:

```bash
$ kubectl port-forward --namespace monitoring deployment/prometheus 9090:9090 &
```

Let's create a metric that reports processes executed:

```yaml
# myconfig.yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
```

Start the gadget

```bash
$ kubectl gadget prometheus --config @myconfig.yaml
INFO[0000] minikube-m02         | Running. Metrics will be updated while this gadget is running
INFO[0000] minikube             | Running. Metrics will be updated while this gadget is running
```

Now, the `executed_processes_total` counter is available in Prometheus:

![Inspektor Gadget Counter Metric](../images/prometheus_counter_1.png)

You can see that the counters are already going up for some containers.

Let's create a pod to execute from more processes:

```bash
$ kubectl run mypod1 -it --image busybox --restart Never -- sh -c 'for i in $(seq 0 1 1000); do cat /dev/null ; ping -c 1 localhost > /dev/null; done'
```

If we check the counter again, we can see that it shows that our pod has executed a lot of processes:

![Inspektor Gadget Counter Metric](../images/prometheus_counter_2.png)

Now, update the configuration file to only take into considerations executions of the `cat` binary:

```yaml
metrics:
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - namespace
      - pod
      - container
    selector:
     - "comm:cat"
```

Restart the gadget

```bash
$ kubectl gadget prometheus --config @myconfig.yaml --metrics-path /metrics
INFO[0000] minikube-m02         | Running. Metrics will be updated while this gadget is running
INFO[0000] minikube             | Running. Metrics will be updated while this gadget is running
```

Create a new pod that executes processes:

```bash
$ kubectl run mypod2 -it --image busybox --restart Never -- sh -c 'for i in $(seq 0 1 1000); do cat /dev/null ; ping -c 1 localhost > /dev/null; done'

```

The counter only takes into consideration the cat commands now:

![Inspektor Gadget Counter Metric](../images/prometheus_counter_3.png)

#### With `ig`

It's also possible to use the prometheus gadget without Kubernetes. In this case, we have to
configure Prometheus to point to the endpoint exposed by ig, it's `localhost:2223` by default:

```yaml
# prometheus.yaml
scrape_configs:
- job_name: ig
  scrape_interval: 1s
  static_configs:
  - targets:
    - localhost:2223
```

Start prometheus with such configuration

```bash
$ prometheus --config.file prometheus.yaml
```

Then, start the prometheus gadget with the same configuration as above:

```bash
$ sudo ig prometheus --config @myconfig.yaml
INFO[0000] Metrics will be updated while this gadget is running.
```

<!-- markdown-link-check-disable-next-line -->
You can check in http://localhost:9090/targets and check that the ig endpoint is reporting metrics:

![ig service up](../images/prometheus_ig_service_up.png)

Let's execute some commands inside a container:

```bash
docker run --rm -ti --name=mycontainer busybox sh -c 'for i in $(seq 0 1 1000); do cat /dev/null ; ping -c 1 localhost > /dev/null; done'
```

We can see how the counter for `mycontainer` is increased.
![ig counter](../images/prometheus_ig_counter1.png)

### Limitations

- The `kubectl gadget` instance has to keep running in order to update the metrics.
- Histograms aren't supported
- It's not possible to configure the metrics endpoint in ig-k8s
