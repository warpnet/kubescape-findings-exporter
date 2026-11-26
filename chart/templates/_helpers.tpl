{{- define "kce.labels" -}}
app.kubernetes.io/name: kubescape-findings-exporter
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kce.selector" -}}
app.kubernetes.io/name: kubescape-findings-exporter
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kce.kubescapeNamespace" -}}
{{ .Values.kubescapeNamespace | default .Release.Namespace }}
{{- end }}
