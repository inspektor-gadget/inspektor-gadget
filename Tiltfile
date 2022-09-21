docker_build(os.environ['CONTAINER_REPO'], '.', dockerfile='Dockerfiles/gadget-default.Dockerfile')

allow_k8s_contexts(os.environ['IG_K8S_CLUSTER'])

contents = """apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: gadget
  namespace: gadget
spec:
  template:
    spec:
      containers:
      - name: gadget
        image: "{}"
        imagePullPolicy: Always""".format(os.environ['CONTAINER_REPO'])

local('echo "$CONTENTS" > {}'.format('pkg/resources/manifests/kustomize/overlay/override_image.yaml'),
      env={'CONTENTS': str(contents)},
      echo_off=True,
      quiet=True)

yaml = kustomize('pkg/resources/manifests/kustomize/overlay')
k8s_yaml(yaml)
k8s_resource('gadget')
