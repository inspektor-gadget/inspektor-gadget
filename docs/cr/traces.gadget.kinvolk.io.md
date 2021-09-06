---
title: Trace CRD schema reference (group gadget.kinvolk.io)
linkTitle: Trace
description: |
  Trace is the Schema for the traces API
weight: 100
crd:
  name_camelcase: Trace
  name_plural: traces
  name_singular: trace
  group: gadget.kinvolk.io
  technical_name: traces.gadget.kinvolk.io
  scope: Namespaced
  source_repository: https://github.com/kinvolk/inspektor-gadget
  source_repository_ref: main
  versions:
    - v1alpha1
  topics:
    - gadget
layout: crd
owner:
  - https://github.com/kinvolk
aliases:
  - /reference/cp-k8s-api/traces.gadget.kinvolk.io/
technical_name: traces.gadget.kinvolk.io
source_repository: https://github.com/kinvolk/inspektor-gadget
source_repository_ref: main
---

# Trace


<p class="crd-description">Trace is the Schema for the traces API</p>
<dl class="crd-meta">
<dt class="fullname">Full name:</dt>
<dd class="fullname">traces.gadget.kinvolk.io</dd>
<dt class="groupname">Group:</dt>
<dd class="groupname">gadget.kinvolk.io</dd>
<dt class="singularname">Singular name:</dt>
<dd class="singularname">trace</dd>
<dt class="pluralname">Plural name:</dt>
<dd class="pluralname">traces</dd>
<dt class="scope">Scope:</dt>
<dd class="scope">Namespaced</dd>
<dt class="versions">Versions:</dt>
<dd class="versions"><a class="version" href="#v1alpha1" title="Show schema for version v1alpha1">v1alpha1</a></dd>
</dl>



<div class="crd-schema-version">
<h2 id="v1alpha1">Version v1alpha1</h2>


<h3 id="crd-example-v1alpha1">Example CR</h3>

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: process-collector
  namespace: gadget
spec:
  node: minikube
  gadget: process-collector
  filter:
    namespace: default
    labels:
      role: demo
  runMode: Manual
  outputMode: Status
```


<h3 id="property-details-v1alpha1">Properties</h3>


<div class="property depth-0">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.apiVersion">.apiVersion</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: <a href="https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources">https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources</a></p>

</div>

</div>
</div>

<div class="property depth-0">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.kind">.kind</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: <a href="https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds">https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds</a></p>

</div>

</div>
</div>

<div class="property depth-0">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.metadata">.metadata</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">object</span>

</div>

</div>
</div>

<div class="property depth-0">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec">.spec</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">object</span>

</div>

<div class="property-description">
<p>TraceSpec defines the desired state of Trace</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.filter">.spec.filter</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">object</span>

</div>

<div class="property-description">
<p>Filter is to tell the gadget to filter events based on namespace, pod name, labels or container name</p>

</div>

</div>
</div>

<div class="property depth-2">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.filter.containerName">.spec.filter.containerName</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>ContainerName selects events from containers with this name</p>

</div>

</div>
</div>

<div class="property depth-2">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.filter.labels">.spec.filter.labels</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">object</span>

</div>

<div class="property-description">
<p>Podname selects events from pods with these labels</p>

</div>

</div>
</div>

<div class="property depth-2">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.filter.namespace">.spec.filter.namespace</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Namespace selects events from this pod namespace</p>

</div>

</div>
</div>

<div class="property depth-2">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.filter.podname">.spec.filter.podname</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Podname selects events from this pod name</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.gadget">.spec.gadget</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Gadget is the name of the gadget such as &ldquo;seccomp&rdquo;</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.node">.spec.node</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Node is the name of the node on which this trace should run</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.output">.spec.output</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Output allows a gadget to output the results in the specified location. * With OutputMode=Status|Stream, Output is unused * With OutputMode=File, Output specifies the file path * With OutputMode=ExternalResource, Output specifies the external   resource (such as   seccompprofiles.security-profiles-operator.x-k8s.io for the   seccomp gadget)</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.outputMode">.spec.outputMode</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>OutputMode is &ldquo;Status&rdquo;, &ldquo;Stream, &ldquo;&ldquo;File&rdquo; or &ldquo;ExternalResource&rdquo;</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.spec.runMode">.spec.runMode</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>RunMode is &ldquo;Auto&rdquo; to automatically start the trace as soon as the resource is created, or &ldquo;Manual&rdquo; to be controlled by the &ldquo;gadget.kinvolk.io/operation&rdquo; annotation</p>

</div>

</div>
</div>

<div class="property depth-0">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.status">.status</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">object</span>

</div>

<div class="property-description">
<p>TraceStatus defines the observed state of Trace</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.status.operationError">.status.operationError</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>OperationError is the error returned by the gadget when applying the annotation gadget.kinvolk.io/operation=</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.status.output">.status.output</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>Output is the output of the gadget</p>

</div>

</div>
</div>

<div class="property depth-1">
<div class="property-header">
<h3 class="property-path" id="v1alpha1-.status.state">.status.state</h3>
</div>
<div class="property-body">
<div class="property-meta">
<span class="property-type">string</span>

</div>

<div class="property-description">
<p>State is &ldquo;Started&rdquo;, &ldquo;Stopped&rdquo; or &ldquo;Completed&rdquo;</p>

</div>

</div>
</div>





</div>



