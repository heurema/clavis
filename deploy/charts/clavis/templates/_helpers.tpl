{{/*
Names. fullname honours a nameOverride-free convention: the release name alone
when it already contains the chart name, otherwise release-chart, truncated to
the 63-character label limit.
*/}}
{{- define "clavis.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "clavis.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "clavis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "clavis.serviceAccountName" -}}
{{- include "clavis.fullname" . -}}
{{- end -}}

{{/*
Labels. selectorLabels are the immutable subset: a Deployment selector cannot
change after creation, so version and managed-by stay out of it.
*/}}
{{- define "clavis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "clavis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "clavis.labels" -}}
helm.sh/chart: {{ include "clavis.chart" . }}
{{ include "clavis.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: server
app.kubernetes.io/part-of: clavis
{{- end -}}

{{/*
Image reference. A digest is immutable and wins over a tag; an empty tag falls
back to the chart's appVersion so a chart release pins a server release.
*/}}
{{- define "clavis.image" -}}
{{- $image := .Values.image -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository (default .Chart.AppVersion $image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
Duration helpers. The server reads Go duration strings, so the chart parses the
same syntax rather than inventing a second one: one or more number-and-unit
pairs using ms, s, m or h, for example 2s, 500ms or 1m30s. The result is
seconds as a float.
*/}}
{{- define "clavis.durationSeconds" -}}
{{- $value := . | toString | trim -}}
{{- if not (regexMatch "^([0-9]+(\\.[0-9]+)?(ms|s|m|h))+$" $value) -}}
{{- fail (printf "clavis: %q is not a supported duration; use Go duration syntax with the units ms, s, m or h, for example 2s, 500ms or 1m30s" $value) -}}
{{- end -}}
{{- $seconds := dict "ms" 0.001 "s" 1.0 "m" 60.0 "h" 3600.0 -}}
{{- $total := dict "value" 0.0 -}}
{{- range $part := regexFindAll "[0-9]+(\\.[0-9]+)?(ms|s|m|h)" $value -1 -}}
{{- $unit := regexFind "(ms|s|m|h)$" $part -}}
{{- $number := float64 (regexFind "^[0-9]+(\\.[0-9]+)?" $part) -}}
{{- $_ := set $total "value" (addf $total.value (mulf $number (index $seconds $unit))) -}}
{{- end -}}
{{- /* A zero timeout is invalid configuration for the server, and a zero
probe timeout or grace period is invalid for Kubernetes. The schema rejects
zero too; this is the gate when schema validation is skipped. */ -}}
{{- if le $total.value 0.0 -}}
{{- fail (printf "clavis: %q must be a positive duration" $value) -}}
{{- end -}}
{{- $total.value -}}
{{- end -}}

{{/*
The readiness probe must outlive the readiness check itself, so its timeout is
the configured database check timeout plus one second, rounded up to the whole
seconds Kubernetes accepts.
*/}}
{{- define "clavis.readinessTimeoutSeconds" -}}
{{- int64 (ceil (addf (float64 (include "clavis.durationSeconds" .)) 1.0)) -}}
{{- end -}}

{{/*
The kubelet must wait longer than the server's own shutdown bound, so the grace
period is the configured shutdown timeout plus five seconds, rounded up.
*/}}
{{- define "clavis.terminationGracePeriodSeconds" -}}
{{- int64 (ceil (addf (float64 (include "clavis.durationSeconds" .)) 5.0)) -}}
{{- end -}}

{{/*
Validation. values.schema.json rejects a missing or non-HTTPS publicURL and the
two required Secret names before rendering starts; these rules are the second
gate, and the only gate for the conditions JSON Schema states badly: mutually
exclusive route kinds and fields required only when bootstrap is enabled.
Every template includes this first, so any render fails with the same message.
*/}}
{{- define "clavis.validate" -}}
{{- if not .Values.publicURL -}}
{{- fail "clavis: publicURL is required; set it to the HTTPS origin this installation is reached on" -}}
{{- end -}}
{{- if not (hasPrefix "https://" .Values.publicURL) -}}
{{- fail (printf "clavis: publicURL must be an https:// origin, got %q" .Values.publicURL) -}}
{{- end -}}
{{- /* A JSON Schema pattern cannot express a duration range, so the bound the
server accepts is checked here instead of being left to a startup failure. */ -}}
{{- $sessionTTL := float64 (include "clavis.durationSeconds" .Values.server.sessionTTL) -}}
{{- if or (lt $sessionTTL 300.0) (gt $sessionTTL 86400.0) -}}
{{- fail (printf "clavis: server.sessionTTL must be between 5m and 24h, got %q" .Values.server.sessionTTL) -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.httpRoute.enabled -}}
{{- fail "clavis: ingress.enabled and httpRoute.enabled are mutually exclusive; enable at most one route kind" -}}
{{- end -}}
{{- if .Values.bootstrap.enabled -}}
{{- if not .Values.bootstrap.username -}}
{{- fail "clavis: bootstrap.username is required when bootstrap.enabled is true" -}}
{{- end -}}
{{- if not .Values.bootstrap.password.secretName -}}
{{- fail "clavis: bootstrap.password.secretName is required when bootstrap.enabled is true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
