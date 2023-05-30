// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestPrometheus(t *testing.T) {
	ns := GenerateTestNamespaceName("test-prometheus")

	// prepare prometheus scrape targets
	gadgetPodIps, err := GetPodIPsFromLabel("gadget", "k8s-app=gadget")
	if err != nil {
		t.Fatalf("failed to get gadget pod ip: %v", err)
	}
	targets := make([]string, 0, len(gadgetPodIps))
	for _, ip := range gadgetPodIps {
		targets = append(targets, fmt.Sprintf("%s:2223", ip))
	}
	scrapeTargets, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("failed to marshal scrape targets: %v", err)
	}

	// set up prometheus pod
	prometheusCmd := &Command{
		Name: "RunPrometheus",
		Cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: %s
data:
  prometheus.yml: |
    global:
      scrape_interval: 10s
      evaluation_interval: 10s

    scrape_configs:
     - job_name: "gadget"

       static_configs:
         - targets: %s
---
apiVersion: v1
kind: Pod
metadata:
  name: prometheus
  namespace: %s
spec:
  terminationGracePeriodSeconds: 0
  containers:
    - name: prometheus
      image: prom/prometheus:v2.44.0
      args:
        - "--config.file=/etc/prometheus/prometheus.yml"
      ports:
        - containerPort: 9090
      volumeMounts:
        - name: config-volume
          mountPath: /etc/prometheus
          readOnly: true
  volumes:
    - name: config-volume
      configMap:
        name: prometheus-config
EOF
`, ns, scrapeTargets, ns),
	}

	RunTestSteps([]*Command{
		CreateTestNamespaceCommand(ns),
		prometheusCmd,
		WaitUntilPodReadyCommand(ns, "prometheus"),
	}, t)

	t.Cleanup(func() {
		cleanupCommands := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(cleanupCommands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("CounterMetrics", func(t *testing.T) {
		counterMetricsCommand := []*Command{
			{
				Name:         "RunPrometheusGadget",
				Cmd:          "$KUBECTL_GADGET prometheus --config @testdata/prometheus/counter.yaml",
				StartAndStop: true,
			},
			SleepForSecondsCommand(2),
			BusyboxPodCommand(ns, "for i in $(seq 1 100); do cat /dev/null; done"),
			SleepForSecondsCommand(30), // wait for prometheus to scrape
			{
				Name: "ValidatePrometheusMetrics",
				Cmd:  fmt.Sprintf("kubectl exec -n %s prometheus -- wget -qO- http://localhost:9090/api/v1/query?query=executed_processes_total", ns),
				ExpectedOutputFn: func(output string) error {
					var prometheusResponse struct {
						Data struct {
							Result json.RawMessage `json:"result"`
						} `json:"data"`
					}
					err = json.Unmarshal([]byte(output), &prometheusResponse)
					if err != nil {
						return fmt.Errorf("marshaling prometheus response: %w", err)
					}

					type Result struct {
						Metric map[string]string `json:"metric"`
						Value  []interface{}     `json:"value"`
					}

					expectedEntry := &Result{
						Metric: map[string]string{
							"__name__":        "executed_processes_total",
							"container":       "test-pod",
							"job":             "gadget",
							"namespace":       ns,
							"pod":             "test-pod",
							"instance":        "",
							"otel_scope_name": "",
						},
						Value: []interface{}{nil, "100"},
					}

					normalize := func(r *Result) {
						r.Value = []interface{}{nil, r.Value[1]}
						r.Metric["instance"] = ""
						r.Metric["otel_scope_name"] = ""
					}

					return ExpectEntriesInArrayToMatch(string(prometheusResponse.Data.Result), normalize, expectedEntry)
				},
			},
		}

		RunTestSteps(counterMetricsCommand, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}
