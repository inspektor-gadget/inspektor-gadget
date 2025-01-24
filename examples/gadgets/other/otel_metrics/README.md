# Open Telemetry Metrics Exporter Operator

This example shows how to export metrics using OpenTelemetry / Prometheus.

### How to run

```bash
$ go run -exec sudo .
```

### What it does

<!-- markdown-link-check-disable-next-line -->
By default, the operator exposes the metrics at http://IP-ADDRESS:2224/metrics (change IP-ADDRESS to your actual IP
address). This demo  uses a counter, gauge and a histogram that emits new values every second. With the provided
annotations, the operator will set those fields up properly and export them.

Note that in this demo no actual gadget is run (thus the image parameter is unused) - instead,
we use a simple operator to emit the metrics.