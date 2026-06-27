{{/*
Expand the name of the chart.
*/}}
{{- define "plainq.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited by the DNS naming spec.
*/}}
{{- define "plainq.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "plainq.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "plainq.labels" -}}
helm.sh/chart: {{ include "plainq.chart" . }}
{{ include "plainq.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "plainq.selectorLabels" -}}
app.kubernetes.io/name: {{ include "plainq.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "plainq.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "plainq.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the name of the Secret holding the JWT secret.
Uses auth.existingSecret when provided, otherwise the chart-managed Secret.
*/}}
{{- define "plainq.jwtSecretName" -}}
{{- if .Values.auth.existingSecret }}
{{- .Values.auth.existingSecret }}
{{- else }}
{{- printf "%s-auth" (include "plainq.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Resolve the name of the Secret holding the Postgres DSN.
*/}}
{{- define "plainq.postgresSecretName" -}}
{{- if .Values.storage.postgres.existingSecret }}
{{- .Values.storage.postgres.existingSecret }}
{{- else }}
{{- printf "%s-postgres" (include "plainq.fullname" .) }}
{{- end }}
{{- end }}
