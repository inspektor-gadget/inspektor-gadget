{{/*
Expand the name of the chart.
*/}}
{{- define "gadget.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "gadget.fullname" -}}
gadget
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "gadget.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace used by all resources.
*/}}
{{- define "gadget.namespace" -}}
{{- .Release.Namespace }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "gadget.labels" -}}
helm.sh/chart: {{ include "gadget.chart" . }}
{{ include "gadget.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: inspektor-gadget
{{- if .Values.additionalLabels.enabled }}
{{- if .Values.additionalLabels }}
{{ toYaml .Values.additionalLabels }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "gadget.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gadget.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/*
Image tag
*/}}
{{- define "gadget.image.tag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag }}
{{- else }}
{{- .Chart.AppVersion }}
{{- end }}
{{- end }}

{{/*
Operator configuration
*/}}
{{- define "gadget.operatorConfig" -}}
{{- $operator := deepCopy .Values.config.operator | default (dict) -}}
{{- if hasKey .Values.config "hookMode" }}
  {{- $merged := mergeOverwrite
      (get $operator "kubemanager" | default dict)
      (dict "hook-mode" .Values.config.hookMode)
    }}
  {{- $operator = set $operator "kubemanager" $merged }}
{{- end }}
{{- if hasKey .Values.config "fallbackPodInformer" }}
  {{- $merged := mergeOverwrite
      (get $operator "kubemanager" | default dict)
      (dict "fallback-podinformer" .Values.config.fallbackPodInformer)
    }}
  {{- $operator = set $operator "kubemanager" $merged }}
{{- end }}
{{- if hasKey .Values.config "verifyGadgets" }}
  {{- $merged := mergeOverwrite
      (get $operator "oci" | default dict)
      (dict "verify-image" .Values.config.verifyGadgets)
    }}
  {{- $operator = set $operator "oci" $merged }}
{{- end }}
{{- if hasKey .Values.config "gadgetsPublicKeys" }}
  {{- $merged := mergeOverwrite
      (get $operator "oci" | default dict)
      (dict "public-keys" .Values.config.gadgetsPublicKeys)
    }}
  {{- $operator = set $operator "oci" $merged }}
{{- end }}
{{- if hasKey .Values.config "allowedGadgets" }}
  {{- $merged := mergeOverwrite
      (get $operator "oci" | default dict)
      (dict "allowed-gadgets" .Values.config.allowedGadgets)
    }}
  {{- $operator = set $operator "oci" $merged }}
{{- end }}
{{- if hasKey .Values.config "disallowGadgetsPulling" }}
  {{- $merged := mergeOverwrite
      (get $operator "oci" | default dict)
      (dict "disallow-pulling" .Values.config.disallowGadgetsPulling)
    }}
  {{- $operator = set $operator "oci" $merged }}
{{- end }}
{{- if hasKey .Values.config "otelMetricsListen" }}
  {{- $merged := mergeOverwrite
      (get $operator "otel-metrics" | default dict)
      (dict "otel-metrics-listen" .Values.config.otelMetricsListen)
    }}
  {{- $operator = set $operator "otel-metrics" $merged }}
{{- end }}
{{- if hasKey .Values.config "otelMetricsAddress" }}
  {{- $merged := mergeOverwrite
      (get $operator "otel-metrics" | default dict)
      (dict "otel-metrics-listen-address" .Values.config.otelMetricsAddress)
    }}
  {{- $operator = set $operator "otel-metrics" $merged }}
{{- end }}
{{- toYaml $operator }}
{{- end }}
