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
