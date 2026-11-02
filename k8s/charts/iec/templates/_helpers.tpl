{{/* 名称辅助 */}}
{{- define "iec.name" -}}
{{- default "iec" .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "iec.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "iec" .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "iec.labels" -}}
app.kubernetes.io/name: {{ include "iec.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "iec.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "iec.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/* 凭据中至少一项非空 (用于决定是否创建 Secret / 注入 envFrom) */}}
{{- define "iec.hasCredentials" -}}
{{- $v := .Values -}}
{{- if or $v.slack.webhook $v.slack.token $v.slack.channel
           $v.alertmanager.url $v.alertmanager.user $v.alertmanager.password -}}
true
{{- else -}}
false
{{- end -}}
{{- end }}
