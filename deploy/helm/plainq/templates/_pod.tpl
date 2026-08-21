{{/*
plainq.args builds the argument list for the "serve" subcommand from values.

PlainQ reads configuration from CLI flags, so authentication credentials are
sourced from Kubernetes Secrets into environment variables and referenced from
the flags with $(VAR). Kubelet expands these references without a shell. The
rendered workload therefore contains only references, never plaintext values.
*/}}
{{- define "plainq.args" -}}
- serve
{{- if and .Values.agent.enabled .Values.agent.developmentInsecureTransport }}
- -grpc.addr=127.0.0.1:{{ .Values.service.grpcPort }}
{{- else }}
- -grpc.addr=:{{ .Values.service.grpcPort }}
{{- end }}
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
- -auth.bootstrap.secret=$(PLAINQ_BOOTSTRAP_SECRET)
{{- else }}
- -auth.enable=false
{{- end }}
- -grpc.protect-legacy={{ if eq .Values.agent.protectLegacy nil }}{{ .Release.IsInstall }}{{ else }}{{ .Values.agent.protectLegacy }}{{ end }}
{{- if .Values.agent.enabled }}
- -agent.enable=true
- -agent.development-insecure-transport={{ .Values.agent.developmentInsecureTransport }}
- -agent.auth.issuer={{ .Values.agent.auth.issuer }}
- -agent.auth.audience={{ .Values.agent.auth.audience }}
- -agent.auth.jwt-secret=$(PLAINQ_AGENT_JWT_SECRET)
- -agent.auth.access-token-ttl={{ .Values.agent.auth.accessTokenTTL }}
- -agent.rate.requests-per-second={{ .Values.agent.rate.requestsPerSecond }}
- -agent.rate.burst={{ .Values.agent.rate.burst }}
{{- if .Values.agent.proxyServerName }}
- -grpc.proxy.server-name={{ .Values.agent.proxyServerName }}
{{- end }}
{{- if not .Values.agent.developmentInsecureTransport }}
- -grpc.tls.mode={{ .Values.agent.tls.mode }}
- -grpc.tls.cert-file=/etc/plainq/grpc-tls/{{ .Values.agent.tls.certKey }}
- -grpc.tls.key-file=/etc/plainq/grpc-tls/{{ .Values.agent.tls.keyKey }}
{{- if eq .Values.agent.tls.mode "mutual" }}
- -grpc.tls.client-ca-file=/etc/plainq/grpc-tls/{{ .Values.agent.tls.clientCAKey }}
{{- end }}
{{- end }}
{{- if .Values.cluster.enabled }}
- -grpc.advertise.addr=$(PLAINQ_POD_IP):{{ .Values.service.grpcPort }}
{{- end }}
{{- else }}
- -agent.enable=false
{{- end }}
- -log.level={{ .Values.config.logLevel }}
- -health.route={{ .Values.config.healthRoute }}
- -metrics.route={{ .Values.config.metricsRoute }}
{{- if .Values.cluster.enabled }}
{{- include "plainq.clusterArgs" . | nindent 0 }}
{{- end }}
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
- name: PLAINQ_BOOTSTRAP_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.bootstrapSecretName" . }}
      key: {{ .Values.auth.bootstrap.secretKey }}
{{- end }}
{{- if .Values.agent.enabled }}
- name: PLAINQ_AGENT_JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.agent.auth.existingSecret | default (printf "%s-agent-auth" (include "plainq.fullname" .)) }}
      key: {{ .Values.agent.auth.secretKey }}
{{- end }}
{{- if eq .Values.storage.driver "postgres" }}
- name: PLAINQ_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.postgresSecretName" . }}
      key: {{ .Values.storage.postgres.secretKey }}
{{- end }}
{{- if .Values.cluster.enabled }}
# The node id must be stable across restarts — the consensus log is keyed on
# it — and unique in the cluster. A StatefulSet pod name is both.
- name: PLAINQ_NODE_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
# Peers dial this pod by IP: the pod binds 0.0.0.0 and advertises this.
- name: PLAINQ_POD_IP
  valueFrom:
    fieldRef:
      fieldPath: status.podIP
- name: PLAINQ_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- if or .Values.cluster.gossipSecret .Values.cluster.existingSecret }}
- name: PLAINQ_GOSSIP_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.clusterSecretName" . }}
      key: {{ .Values.cluster.gossipSecretKey }}
{{- end }}
{{- if or .Values.cluster.secret .Values.cluster.existingSecret }}
- name: PLAINQ_CLUSTER_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "plainq.clusterSecretName" . }}
      key: {{ .Values.cluster.secretKey }}
{{- end }}
{{- end }}
{{- with .Values.env }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
plainq.clusterArgs builds the -cluster.* flags.

Discovery answers with gossip addresses; a peer's consensus address is part of
what it gossips, so only one port has to be discoverable.
*/}}
{{- define "plainq.clusterArgs" -}}
- -cluster.enable=true
- -cluster.node-id=$(PLAINQ_NODE_ID)
- -cluster.bind.addr=0.0.0.0:{{ .Values.cluster.clusterPort }}
- -cluster.advertise.addr=$(PLAINQ_POD_IP):{{ .Values.cluster.clusterPort }}
- -cluster.gossip.addr=0.0.0.0:{{ .Values.cluster.gossipPort }}
- -cluster.gossip.advertise.addr=$(PLAINQ_POD_IP):{{ .Values.cluster.gossipPort }}
- -cluster.bootstrap-expect={{ .Values.cluster.replicas }}
- -cluster.consistency={{ .Values.cluster.consistency }}
- -cluster.discovery={{ include "plainq.discoverySpec" . }}
- -cluster.auto-remove={{ .Values.cluster.autoRemove }}
- -cluster.remove.timeout={{ .Values.cluster.removeTimeout }}
{{- if or .Values.cluster.gossipSecret .Values.cluster.existingSecret }}
- -cluster.gossip.secret=$(PLAINQ_GOSSIP_SECRET)
{{- end }}
{{- if or .Values.cluster.secret .Values.cluster.existingSecret }}
- -cluster.secret=$(PLAINQ_CLUSTER_SECRET)
{{- end }}
{{- with .Values.cluster.extraArgs }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
plainq.discoverySpec renders the discovery spec.

The Kubernetes provider is the default because it sees pods that are not ready
yet — and no PlainQ pod is ready until it has joined a cluster, which it cannot
do without seeing its peers. DNS discovery avoids the RBAC grant but only
resolves ready endpoints, so it suits adding nodes to a cluster that already
exists rather than forming one.
*/}}
{{- define "plainq.discoverySpec" -}}
{{- if .Values.cluster.discoveryOverride -}}
{{ .Values.cluster.discoveryOverride }}
{{- else if eq .Values.cluster.discovery "dns" -}}
dns://{{ include "plainq.fullname" . }}-headless.$(PLAINQ_NAMESPACE).svc.cluster.local?port={{ .Values.cluster.gossipPort }}
{{- else -}}
kubernetes://?namespace=$(PLAINQ_NAMESPACE)&selector=app.kubernetes.io%2Fname%3D{{ include "plainq.name" . }}%2Capp.kubernetes.io%2Finstance%3D{{ .Release.Name }}&port={{ .Values.cluster.gossipPort }}
{{- end -}}
{{- end }}

{{/*
plainq.containerSpec renders the shared PlainQ container definition for both the
StatefulSet (sqlite) and the Deployment (postgres).
*/}}
{{- define "plainq.containerSpec" -}}
- name: {{ .Chart.Name }}
  securityContext:
    {{- toYaml .Values.securityContext | nindent 4 }}
  {{- if .Values.image.digest }}
  image: "{{ .Values.image.repository }}@{{ .Values.image.digest }}"
  {{- else }}
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  {{- end }}
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
    {{- if .Values.cluster.enabled }}
    - name: cluster
      containerPort: {{ .Values.cluster.clusterPort }}
      protocol: TCP
    - name: gossip-tcp
      containerPort: {{ .Values.cluster.gossipPort }}
      protocol: TCP
    - name: gossip-udp
      containerPort: {{ .Values.cluster.gossipPort }}
      protocol: UDP
    {{- end }}
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
    {{- if and .Values.agent.enabled (not .Values.agent.developmentInsecureTransport) }}
    - name: grpc-tls
      mountPath: /etc/plainq/grpc-tls
      readOnly: true
    {{- end }}
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
{{- if and .Values.agent.enabled (not .Values.agent.developmentInsecureTransport) }}
- name: grpc-tls
  secret:
    secretName: {{ .Values.agent.tls.existingSecret }}
{{- end }}
{{- if and (eq .Values.storage.driver "sqlite") (not .Values.storage.sqlite.persistence.enabled) }}
- name: data
  emptyDir: {}
{{- end }}
{{- end }}
