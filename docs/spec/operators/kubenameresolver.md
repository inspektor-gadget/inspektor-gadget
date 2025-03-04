---
title: KubeNameResolver
---

The KubeNameResolver operator uses the `K8s.PodName` and `K8s.Namespace` fields to enrich the event with `K8s.PodIp` and `K8s.HostIp` fields. 
This operator is disabled by default (See [annotation](#annotation) for how to enable it).

The example below shows a request from `test-pod` pod in json format:

Without `KubeNameResolver`:
```json
{
  ...
  "k8s": {
    "containerName": "test-pod",
    "hostnetwork": false,
    "namespace": "default",
    "node": "minikube-docker",
    "owner": {
      "kind": "",
      "name": ""
    },
    "podLabels": "run=test-pod",
    "podName": "test-pod"
  },
  "proc": {
    "comm": "wget",
    ...
  },
  ...
}
```

With `KubeNameResolver`:
```json
{
  ...
  "k8s": {
    "containerName": "test-pod",
    "hostIP": "192.168.58.2",
    "hostnetwork": false,
    "namespace": "default",
    "node": "minikube-docker",
    "owner": {
      "kind": "",
      "name": ""
    },
    "podIP": "10.244.0.29",
    "podLabels": "run=test-pod",
    "podName": "test-pod"
  },
  "proc": {
    "comm": "wget",
    ...
  },
  ...
}
```

## Priority

11

## Parameters

None

## Annotation

This operator is disabled by default and is only activated for a datasource if it has the following annotations:
datasource_name:
  annotations:
    kubenameresolver.enable: true    
```
