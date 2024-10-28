# monitoring

This directory contains docker compose files for spinning up grafana and prometheus for local testing.
Prometheus is configured to scrape metrics from the `ig` daemon running on the host machine as:

```bash
go run -exec sudo ../../cmd/ig daemon --otel-metrics-listen=true
```

then start the gadget with

```bash
go run -exec 'sudo -E' ../../cmd/gadgetctl run ghcr.io/inspektor-gadget/gadget/profile_blockio:latest \
        --annotate=blockio:metrics.collect=true \
        --otel-metrics-name=blockio:blockio-metrics \
        --detach
```

feel free to have a look at [export-metrics](https://www.inspektor-gadget.io/docs/latest/reference/export-metrics) guide for more information.

Once the gadget is running, you can start the monitoring stack with:

```bash
docker compose up -d
```

<!-- markdown-link-check-disable -->
Grafana will be available at http://localhost:3000 and prometheus at http://localhost:9090.
Also, head to [Profile Block I/O dashboard](http://localhost:3000/d/e1981f70-308c-4784-b986-9b5f1a895444/inspektor-gadget) to see the metrics.
<!-- markdown-link-check-enable -->

### Cleanup

```bash
docker compose down
```

