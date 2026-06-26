{{/*
plainq.args builds the argument list for the "serve" subcommand from values.

Note on the JWT secret: PlainQ only reads configuration from CLI flags, not env
vars. We still source the secret value from a Kubernetes Secret (never inlined in
the manifest) by exposing it as the env var PLAINQ_JWT_SECRET and referencing it
in the flag with $(PLAINQ_JWT_SECRET). Kubernetes expands $(VAR) references in
container args itself — this is a native kubelet feature, not a shell feature, so
it works on a distroless image with no shell. The expanded plaintext secret never
appears in the rendered manifest, only the variable reference does.
*/}}
{{- define "plainq.args" -}}
- serve
- -grpc.addr=:{{ .Values.service.grpcPort }}
- -http.addr=:{{ .Values.service.httpPort }}
- -storage.driver={{ .Values.storage.driver }}
{{- if eq .Values.storage.driver "sqlite" }}
- -storage.path={{ .Values.storage.sqlite.path }}
{{- else }}
- -storage.postgres.dsn=$(PLAINQ_POSTGRES_DSN)
{{- end }}
{{- if .Values.auth.enabled }}
- -auth.enable=true
- -auth.jwt.secret=$(PLAINQ_JWT_SECRET)
{{- else }}
- -auth.enable=false
{{- end }}
- -log.level={{ .Values.config.logLevel }}
- -health.route={{ .Values.config.healthRoute }}
- -metrics.route={{ .Values.config.metricsRoute }}
{{- with .Values.extraArgs }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
plainq.env builds the environment list: the secret-sourced values used by the
$(VAR) expansion above, plus any user-supplied env.
*/}}
{{- define "plainq.env" -}}
{{- if .Values.auth.enabled -}}
- name: PLAINQ_JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.jwtSecretName" . }}
      key: {{ .Values.auth.secretKey }}
{{- end }}
{{- if eq .Values.storage.driver "postgres" }}
- name: PLAINQ_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.postgresSecretName" . }}
      key: {{ .Values.storage.postgres.secretKey }}
{{- end }}
{{- with .Values.env }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
plainq.containerSpec renders the shared PlainQ container definition for both the
StatefulSet (sqlite) and the Deployment (postgres).
*/}}
{{- define "plainq.containerSpec" -}}
- name: {{ .Chart.Name }}
  securityContext:
    {{- toYaml .Values.securityContext | nindent 4 }}
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
    {{- include "plainq.args" . | nindent 4 }}
  env:
    {{- include "plainq.env" . | nindent 4 }}
  {{- with .Values.envFrom }}
  envFrom:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  ports:
    - name: grpc
      containerPort: {{ .Values.service.grpcPort }}
      protocol: TCP
    - name: http
      containerPort: {{ .Values.service.httpPort }}
      protocol: TCP
  livenessProbe:
    {{- toYaml .Values.livenessProbe | nindent 4 }}
  readinessProbe:
    {{- toYaml .Values.readinessProbe | nindent 4 }}
  resources:
    {{- toYaml .Values.resources | nindent 4 }}
  volumeMounts:
    # /tmp is writable scratch space, required because readOnlyRootFilesystem is true.
    - name: tmp
      mountPath: /tmp
    {{- if eq .Values.storage.driver "sqlite" }}
    - name: data
      mountPath: {{ dir .Values.storage.sqlite.path }}
    {{- end }}
{{- end }}

{{/*
plainq.volumes renders the shared pod-level volumes.
*/}}
{{- define "plainq.volumes" -}}
- name: tmp
  emptyDir: {}
{{- if and (eq .Values.storage.driver "sqlite") (not .Values.storage.sqlite.persistence.enabled) }}
- name: data
  emptyDir: {}
{{- end }}
{{- end }}
