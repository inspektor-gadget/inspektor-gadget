# Rapid iterative development using Tilt

## Requirements

- [Tilt](https://tilt.dev/)
- kubectl

## Workflow

Set your environment:

```shell
# Name of your cluster's k8s context (check kubectl config get-contexts).
export IG_K8S_CLUSTER=my-cluster
# A Docker repository to use for development. Tilt will push temporary images there.
export CONTAINER_REPO=quay.io/me/inspektor-gadget
```

Ensure you are logged into your Docker registry (run `docker login` if necessary).

Run Tilt:

```shell
tilt up
```

Hit Space and watch the progress in your browser. If you leave Tilt running in the background, any
Tilt would rebuild, push and redeploy any code changes automatically when you modify source files.
