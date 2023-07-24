# monitoring

This directory contains docker compose files for spinning up grafana and prometheus for local testing.
Prometheus is configured to scrape metrics from the `ig` instance running on the host machine as:

```bash
go run -exec sudo ../../cmd/ig/ prometheus --config @config/histogram.yaml
INFO[0000] Running. Press Ctrl + C to finish
...
```

The monitoring containers can be started with:

```bash
docker compose up -d
```

<!-- markdown-link-check-disable-next-line -->
Grafana will be available at http://localhost:3000 and prometheus at http://localhost:9090.

To remove the containers:

```bash
docker compose down
```

