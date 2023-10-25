#ifndef GADGET_METRICS
#define GADGET_METRICS

#ifndef METRICS_MAX_ENTRIES
#define METRICS_MAX_ENTRIES 10240
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

{{- range . }}

{{- $Metric := . }}
{{- $MetricName := .MetricName }}
{{- $MetricsMap := (printf "metrics_map_%s" $MetricName) }}
{{- $MetricsKeyStruct := (printf "metrics_key_%s_t" $MetricName) }}
{{- $MetricsValStruct := (printf "metrics_val_%s_t" $MetricName) }}
{{- $MetricsKeyScratchMap := (printf "tmp_metrics_key_%s_t" $MetricName) }}

// {{ $MetricName }}
//////////////////////////////////

{{- range .Labels }}
const volatile __u32 metrics_key_{{ $MetricName }}_{{ .Name }}_enabled = 1;
{{- end }}

// Key for "{{ $MetricName }}"
struct __attribute__((__packed__)) {{ $MetricsKeyStruct }} {
{{- range .Labels }}
	{{ .CType }} {{ .Name }};
{{- end }}
};

// Value for "{{ $MetricName }}"
struct {{ $MetricsValStruct }} {
{{- range .Values }}
	{{ .CType }} {{ .Name }};
{{- end }}
};

// Map for storing "{{ $MetricName }}"
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, METRICS_MAX_ENTRIES);
	__type(key, struct {{ $MetricsKeyStruct }});
	__type(value, struct {{ $MetricsValStruct }});
} {{ $MetricsMap }} SEC(".maps");

// Reference structs to keep them alive
const struct {{ $MetricsKeyStruct }} *unused_{{ $MetricsKeyStruct }} __attribute__((unused));
const struct {{ $MetricsValStruct }} *unused_{{ $MetricsValStruct }} __attribute__((unused));

// Scratch map for "{{ $MetricName }}" key
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_key_{{ $MetricName }}_t);
} {{ $MetricsKeyScratchMap }} SEC(".maps");

// metrics_{{ $MetricName }}_get_entry gets the metric entry for the given keys
// always inline due to param limit restriction
static __always_inline struct {{ $MetricsValStruct }}* metrics_{{ $MetricName }}_get_entry(
{{- range $i, $Field := .Labels -}}
	{{ if ne $i 0 }},{{ end }}
	{{ .CType }}* {{ .Name }}
{{- end }}
) {
	const int metric_len =
{{- range $i, $Field := .Labels }}
		{{ if ne $i 0 }}+ {{ end }}(metrics_key_{{ $MetricName }}_{{ .Name }}_enabled * sizeof({{ .CType }}))
{{- end }};
	__u32 zero = 0;
	const unsigned char* key = bpf_map_lookup_elem(&{{ $MetricsKeyScratchMap }}, &zero);
	if (!key) return NULL;

	// prepare key
	int offs = 0;
{{- range $i, $Field := .Labels }}
	if (metrics_key_{{ $MetricName }}_{{ .Name }}_enabled) {
		__builtin_memcpy((void*)key + offs, (void*){{ .Name }}, sizeof({{ .CType }}));
		offs += sizeof({{ .CType }});
	}
{{- end }};

	// fetch entry
	struct {{ $MetricsValStruct }}* values = bpf_map_lookup_elem(&{{ $MetricsMap }}, key);
	if (values == NULL) {
		struct {{ $MetricsValStruct }} emptyMetrics = {};
		bpf_map_update_elem(&{{ $MetricsMap }}, key, &emptyMetrics, BPF_NOEXIST);
		values = bpf_map_lookup_elem(&{{ $MetricsMap }}, key);
	}
	return values;
};

{{ range $i, $Field := .Values -}}
void metrics_{{ $MetricName }}_set_{{ .Name }}(struct {{ $MetricsValStruct }}* values, {{ .CType }}* val) {
	__builtin_memcpy((void*)values + offsetof(struct {{ $MetricsValStruct }}, {{ .Name }}), val, sizeof({{ .CType }}));
}

void metrics_{{ $MetricName }}_add_{{ .Name }}(struct {{ $MetricsValStruct }}* values, {{ .CType }} val) {
	__sync_fetch_and_add(({{ .CType }}*)((void*)values + offsetof(struct {{ $MetricsValStruct }}, {{ .Name }})), val);
}

{{ end }}

{{- end -}}

#endif