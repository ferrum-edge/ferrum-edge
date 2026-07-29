{{/*
Ferrum mesh chart helpers. These helpers intentionally fail at template time for
invalid CP settings so an unusable control-plane pod is not rendered.
*/}}

{{- define "ferrum-mesh.validateOneSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if ne $count 1 -}}
{{- fail (printf "%s requires exactly one of value, existingSecret.name, or valueFrom" $label) -}}
{{- end -}}
{{- if and $source.value .minLength (lt (len $source.value) .minLength) -}}
{{- fail (printf "%s.value must be at least %d characters" $label (.minLength | int)) -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateControlPlaneInputs" -}}
{{- $needsCpConfig := or .Values.controlPlane.enabled .Values.ca.enabled -}}
{{- if $needsCpConfig -}}
{{- $cp := .Values.controlPlane | default dict -}}
{{- $env := $cp.env | default dict -}}
{{- range $reserved := list "FERRUM_DB_TYPE" "FERRUM_DB_URL" "FERRUM_ADMIN_JWT_SECRET" "FERRUM_CP_DP_GRPC_JWT_SECRET" -}}
{{- if hasKey $env $reserved -}}
{{- fail (printf "controlPlane.env.%s is reserved; use controlPlane.database or controlPlane.credentials instead" $reserved) -}}
{{- end -}}
{{- end -}}
{{- $db := $cp.database | default dict -}}
{{- if not $db.type -}}
{{- fail "controlPlane.database.type is required when controlPlane.enabled or ca.enabled is true" -}}
{{- end -}}
{{- if not (has $db.type (list "sqlite" "postgres" "mysql" "mongodb")) -}}
{{- fail "controlPlane.database.type must be one of: sqlite, postgres, mysql, mongodb" -}}
{{- end -}}
{{- $urlFromCount := 0 -}}
{{- $existingDb := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
{{- if $db.url -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $db.urlFrom -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $existingDb.name -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if and (eq $db.type "sqlite") $sqlite.path -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $db.host -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if ne $urlFromCount 1 -}}
{{- fail "controlPlane.database requires exactly one URL source: url, urlFrom, existingSecret.name, sqlite.path, or structured host settings" -}}
{{- end -}}
{{- if and (ne $db.type "sqlite") $sqlite.path -}}
{{- fail "controlPlane.database.sqlite.path is valid only when controlPlane.database.type=sqlite" -}}
{{- end -}}
{{- if and (eq $db.type "sqlite") $db.host -}}
{{- fail "controlPlane.database.host is not valid when controlPlane.database.type=sqlite" -}}
{{- end -}}
{{- if and $db.host (or (eq $db.type "postgres") (eq $db.type "mysql")) (not $db.name) -}}
{{- fail "controlPlane.database.name is required for structured postgres/mysql database URLs" -}}
{{- end -}}
{{- $credSecret := $db.existingCredentialsSecret | default dict -}}
{{- if or $db.usernameFrom $db.passwordFrom $credSecret.name -}}
{{- fail "controlPlane.database structured Secret-backed username/password cannot be safely percent-encoded into FERRUM_DB_URL; use controlPlane.database.existingSecret or urlFrom with a fully encoded URL Secret instead" -}}
{{- end -}}
{{- if or $db.username $db.password -}}
{{- if not $db.host -}}{{- fail "controlPlane.database username/password require structured host settings" -}}{{- end -}}
{{- if not (and $db.username $db.password) -}}{{- fail "controlPlane.database structured credentials require both username and password, or neither" -}}{{- end -}}
{{- end -}}
{{- $creds := $cp.credentials | default dict -}}
{{- include "ferrum-mesh.validateOneSource" (dict "label" "controlPlane.credentials.adminJwtSecret" "source" ($creds.adminJwtSecret | default dict) "minLength" 32) -}}
{{- include "ferrum-mesh.validateOneSource" (dict "label" "controlPlane.credentials.cpDpGrpcJwtSecret" "source" ($creds.cpDpGrpcJwtSecret | default dict) "minLength" 32) -}}
{{/* Advisory GHSA-3f2j-wwqw-grmg: the fleet-wide cpDpGrpcJwtSecret is handed to
     the very data planes it authorizes, so it cannot separate tenants. A CP
     serving more than one namespace (FERRUM_CP_NAMESPACES naming a set, or "*")
     REFUSES TO START without FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH
     (src/modes/control_plane.rs / src/grpc/cp_trust.rs). Mirror that at render
     so the failure is a helm error, not a crash-looping pod that times out
     live CI installs. */}}
{{- $cpNamespacesRaw := "" -}}
{{- if hasKey $env "FERRUM_CP_NAMESPACES" -}}
{{- $cpNamespacesRaw = index $env "FERRUM_CP_NAMESPACES" | toString -}}
{{- end -}}
{{- $cpNsList := compact (splitList "," ($cpNamespacesRaw | replace " " "")) -}}
{{- $cpMultiNamespace := or (has "*" $cpNsList) (gt (len $cpNsList) 1) -}}
{{- $cpTrustBundle := "" -}}
{{- if hasKey $env "FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH" -}}
{{- $cpTrustBundle = index $env "FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH" | toString | trim -}}
{{- end -}}
{{- if and $cpMultiNamespace (eq $cpTrustBundle "") -}}
{{- fail (printf "controlPlane.env.FERRUM_CP_NAMESPACES=%q makes this a multi-namespace control plane, which refuses to start with only controlPlane.credentials.cpDpGrpcJwtSecret: that value is distributed to the data planes it would authorize, so any tenant holding it can re-sign the JWT `ns` claim and subscribe to another tenant (advisory GHSA-3f2j-wwqw-grmg). Set controlPlane.env.FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH to a mounted JSON bundle of namespace-bound verification credentials (see docs/cp_namespace_tenancy.md), or serve one namespace per CP via FERRUM_NAMESPACE / a single FERRUM_CP_NAMESPACES entry." $cpNamespacesRaw) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.renderSecretEnv" -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
- name: {{ .name }}
{{- if $source.valueFrom }}
  valueFrom:
{{ toYaml $source.valueFrom | nindent 4 }}
{{- else if $existing.name }}
  valueFrom:
    secretKeyRef:
      name: {{ $existing.name | quote }}
      key: {{ default .defaultKey $existing.key | quote }}
{{- else }}
  value: {{ $source.value | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-mesh.uriComponentEncode" -}}
{{- . | toString | urlquery | replace "+" "%20" -}}
{{- end -}}

{{- define "ferrum-mesh.structuredDbUrl" -}}
{{- $db := . -}}
{{- $port := "" -}}
{{- if $db.port -}}{{- $port = printf ":%v" $db.port -}}{{- end -}}
{{- $host := $db.host -}}
{{- if and (contains ":" $host) (not (hasPrefix "[" $host)) -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- $auth := "" -}}
{{- if and $db.username $db.password -}}
{{- $auth = printf "%s:%s@" (include "ferrum-mesh.uriComponentEncode" $db.username) (include "ferrum-mesh.uriComponentEncode" $db.password) -}}
{{- end -}}
{{- $path := "" -}}
{{- if $db.name -}}{{- $path = printf "/%s" (include "ferrum-mesh.uriComponentEncode" $db.name) -}}{{- end -}}
{{- $query := "" -}}
{{- if $db.params -}}
{{- $pairs := list -}}
{{- range $key := keys $db.params | sortAlpha -}}
{{- $pairs = append $pairs (printf "%s=%s" (include "ferrum-mesh.uriComponentEncode" $key) (include "ferrum-mesh.uriComponentEncode" (get $db.params $key))) -}}
{{- end -}}
{{- if $pairs -}}{{- $query = printf "?%s" (join "&" $pairs) -}}{{- end -}}
{{- end -}}
{{- printf "%s://%s%s%s%s%s" $db.type $auth $host $port $path $query -}}
{{- end -}}

{{- define "ferrum-mesh.renderDbUrlEnv" -}}
{{- $db := .Values.controlPlane.database | default dict -}}
{{- $existing := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
- name: FERRUM_DB_URL
{{- if $db.urlFrom }}
  valueFrom:
{{ toYaml $db.urlFrom | nindent 4 }}
{{- else if $existing.name }}
  valueFrom:
    secretKeyRef:
      name: {{ $existing.name | quote }}
      key: {{ default "url" $existing.urlKey | quote }}
{{- else if $db.url }}
  value: {{ $db.url | quote }}
{{- else if and (eq $db.type "sqlite") $sqlite.path }}
  value: {{ printf "sqlite:%s?mode=%s" $sqlite.path (default "rwc" $sqlite.mode) | quote }}
{{- else }}
  value: {{ include "ferrum-mesh.structuredDbUrl" $db | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-mesh.renderControlPlaneRequiredEnv" -}}
{{- $cp := .Values.controlPlane | default dict -}}
{{- $db := $cp.database | default dict -}}
{{- $creds := $cp.credentials | default dict -}}
- name: FERRUM_DB_TYPE
  value: {{ $db.type | quote }}
{{ include "ferrum-mesh.renderDbUrlEnv" . }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_ADMIN_JWT_SECRET" "source" ($creds.adminJwtSecret | default dict) "defaultKey" "admin-jwt-secret") }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" ($creds.cpDpGrpcJwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end -}}

{{/*
Normalize an admin bind address into the host the in-pod exec probe must dial.
Wildcards become loopback; concrete binds are used as-is.
*/}}
{{- define "ferrum-mesh.adminProbeHost" -}}
{{- $bind := toString . -}}
{{- if or (eq $bind "") (eq $bind "0.0.0.0") (eq $bind "*") -}}
127.0.0.1
{{- else if eq $bind "::" -}}
::1
{{- else -}}
{{- $bind -}}
{{- end -}}
{{- end -}}

{{/*
Resolve admin HTTP port/bind from a workload env map, falling back to binary
defaults (9000 / 127.0.0.1). Returns a dict with keys port, bind, probeHost.
*/}}
{{- define "ferrum-mesh.adminProbeTargetFromEnv" -}}
{{- $env := . | default dict -}}
{{- $port := "9000" -}}
{{- if hasKey $env "FERRUM_ADMIN_HTTP_PORT" -}}
{{- $port = toString (index $env "FERRUM_ADMIN_HTTP_PORT") -}}
{{- end -}}
{{- $bind := "127.0.0.1" -}}
{{- if hasKey $env "FERRUM_ADMIN_BIND_ADDRESS" -}}
{{- $bind = toString (index $env "FERRUM_ADMIN_BIND_ADDRESS") -}}
{{- end -}}
{{- dict "port" $port "bind" $bind "probeHost" (include "ferrum-mesh.adminProbeHost" $bind) | toYaml -}}
{{- end -}}

{{/*
Build the process-only (/live) and dependency-aware (/health) exec handlers for
workloads that expose the admin listener. Liveness/startup MUST use --live so an
alive-but-degraded process is not restart-looped.

Command argv is kept as a Helm list here; `ferrum-mesh.renderProbeHandler` emits
each item with `| quote` so hosts like `::1` / `127.0.0.1` and ports stay
double-quoted in the rendered manifest (go-yaml's plain `toYaml` leaves those
bare, which breaks frozen NodeWaypoint chart assertions).
*/}}
{{- define "ferrum-mesh.adminHealthHandlers" -}}
{{- $port := toString .port -}}
{{- $host := toString .probeHost -}}
{{- $liveCmd := list "/app/ferrum-edge" "health" "--live" "-p" $port "--host" $host -}}
{{- $readyCmd := list "/app/ferrum-edge" "health" "-p" $port "--host" $host -}}
{{- dict "live" (dict "exec" (dict "command" $liveCmd)) "ready" (dict "exec" (dict "command" $readyCmd)) | toYaml -}}
{{- end -}}

{{/*
Render one probe handler. Exec command lists are emitted item-by-item with
`| quote` so IPv6/IPv4 probe hosts and numeric ports match the quoted spelling
required by tests/k8s/node_waypoint_ebpf_live/run.sh. Non-exec handlers
(tcpSocket, httpGet overrides, …) still use toYaml.
*/}}
{{- define "ferrum-mesh.renderProbeHandler" -}}
{{- if and .exec .exec.command -}}
exec:
  command:
{{- range .exec.command }}
  - {{ . | quote }}
{{- end }}
{{- else -}}
{{- toYaml . }}
{{- end -}}
{{- end -}}

{{/*
Render independently configurable startup/liveness/readiness probes.
Required dict keys:
  probes       - values.<workload>.probes
  liveHandler  - non-empty handler used by startup + liveness (empty → skip)
  readyHandler - non-empty handler used by readiness (empty → skip)
*/}}
{{- define "ferrum-mesh.renderProbes" -}}
{{- $probes := .probes | default dict -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $liveHandler := .liveHandler | default dict -}}
{{- $readyHandler := .readyHandler | default dict -}}
{{- if and ($startup.enabled | default false) $liveHandler }}
          startupProbe:
            {{- /* Startup shares the process-only liveness handler. Pointing it
                   at dependency-aware readiness would kill a pod that boots but
                   stays legitimately unready (cert/config/CP wait). */}}
            {{- include "ferrum-mesh.renderProbeHandler" $liveHandler | nindent 12 }}
            failureThreshold: {{ $startup.failureThreshold }}
            periodSeconds: {{ $startup.periodSeconds }}
{{- end }}
{{- if and ($liveness.enabled | default false) $liveHandler }}
          livenessProbe:
            {{- include "ferrum-mesh.renderProbeHandler" $liveHandler | nindent 12 }}
            initialDelaySeconds: {{ $liveness.initialDelaySeconds }}
            periodSeconds: {{ $liveness.periodSeconds }}
{{- end }}
{{- if and ($readiness.enabled | default false) $readyHandler }}
          readinessProbe:
            {{- include "ferrum-mesh.renderProbeHandler" $readyHandler | nindent 12 }}
            initialDelaySeconds: {{ $readiness.initialDelaySeconds }}
            periodSeconds: {{ $readiness.periodSeconds }}
{{- end }}
{{- end -}}
