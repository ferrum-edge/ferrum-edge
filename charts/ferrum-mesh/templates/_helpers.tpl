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
{{- range $reserved := list "FERRUM_DB_TYPE" "FERRUM_DB_URL" "FERRUM_ADMIN_JWT_SECRET" "FERRUM_CP_DP_GRPC_JWT_SECRET" "FERRUM_SHUTDOWN_DRAIN_SECONDS" "FERRUM_SHUTDOWN_PREDRAIN_SECONDS" "FERRUM_METRICS_BEARER_TOKEN" "FERRUM_METRICS_ALLOWED_CIDRS" -}}
{{- if hasKey $env $reserved -}}
{{- fail (printf "controlPlane.env.%s is reserved; use controlPlane.database, controlPlane.credentials, controlPlane shutdown values, or observability.metrics instead" $reserved) -}}
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
Build the process-only (/live) and dependency-aware (/health) exec handlers for
workloads that expose the admin listener. Liveness/startup MUST use --live so an
alive-but-degraded process is not restart-looped.

Dict keys:
  port      - listen port
  probeHost - dial host for in-pod exec
  tls       - optional; when truthy, append --tls --tls-no-verify (HTTPS-only)

Command argv is kept as a Helm list here; `ferrum-mesh.renderProbeHandler` emits
each item with `| quote` so hosts like `::1` / `127.0.0.1` and ports stay
double-quoted in the rendered manifest (go-yaml's plain `toYaml` leaves those
bare, which breaks frozen NodeWaypoint chart assertions).
*/}}
{{- define "ferrum-mesh.adminHealthHandlers" -}}
{{- $port := toString .port -}}
{{- $host := toString .probeHost -}}
{{- $tls := .tls | default false -}}
{{- $liveCmd := list "/app/ferrum-edge" "health" "--live" "-p" $port "--host" $host -}}
{{- $readyCmd := list "/app/ferrum-edge" "health" "-p" $port "--host" $host -}}
{{- if $tls -}}
{{- $liveCmd = list "/app/ferrum-edge" "health" "--live" "--tls" "--tls-no-verify" "-p" $port "--host" $host -}}
{{- $readyCmd = list "/app/ferrum-edge" "health" "--tls" "--tls-no-verify" "-p" $port "--host" $host -}}
{{- end -}}
{{- dict "live" (dict "exec" (dict "command" $liveCmd)) "ready" (dict "exec" (dict "command" $readyCmd)) | toYaml -}}
{{- end -}}

{{/*
Resolve whether node-agent admin TLS Secret mounts are fully configured.
Returns the string "true" or empty.
*/}}
{{- define "ferrum-mesh.nodeAgentAdminTlsConfigured" -}}
{{- $tls := . | default dict -}}
{{- if and $tls.enabled $tls.secretName $tls.certKey $tls.keyKey -}}
true
{{- end -}}
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
  probes         - values.<workload>.probes
  liveHandler    - non-empty handler used by liveness (empty → skip)
  readyHandler   - non-empty handler used by readiness (empty → skip)
Optional:
  startupHandler - non-empty handler used by startup. When omitted/empty,
                   startup falls back to liveHandler (backward-compatible:
                   a liveness.override still reaches startup unless an
                   explicit startup.override is supplied).
*/}}
{{- define "ferrum-mesh.renderProbes" -}}
{{- $probes := .probes | default dict -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $liveHandler := .liveHandler | default dict -}}
{{- $readyHandler := .readyHandler | default dict -}}
{{- $startupHandler := .startupHandler | default dict -}}
{{- if not $startupHandler -}}{{- $startupHandler = $liveHandler -}}{{- end -}}
{{- if and ($startup.enabled | default false) $startupHandler }}
          startupProbe:
            {{- /* Prefer a process-only handler (--live / TCP accept). Pointing
                   startup at dependency-aware readiness would kill a pod that
                   boots but stays legitimately unready (cert/config/CP wait). */}}
            {{- include "ferrum-mesh.renderProbeHandler" $startupHandler | nindent 12 }}
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
            {{- /* Rendered explicitly when set: failureThreshold × periodSeconds
                   is probe-driven endpoint-removal latency and pairs with
                   shutdownPreStopSeconds (issue #4266). */}}
            {{- if hasKey $readiness "failureThreshold" }}
            failureThreshold: {{ $readiness.failureThreshold }}
            {{- end }}
{{- end }}
{{- end -}}

{{/*
Release-bound node-proof generation for the Ambient UDP placement contract
(issue #3809).

The node-scoped cleanup attestation must be bound to a generation that cannot
RECUR, so an attestation written for one placement era can never authorize a
later one. This helper therefore reads ONLY the installed contract's persisted,
era-qualified `nodeProofGeneration` (`e<era>.<migration generation>`, stamped by
`udp-placement-contract.yaml` when a migration starts and carried forward
unchanged through finalize and every settled release after it).

It deliberately has NO derived fallback. A token derived from the release's
observable shape — `<target>-<phase>` — repeats the moment a target and phase
recur, so after a host -> pod -> host round trip an old settled-host proof would
name the NEW host era and a same-boot node that missed the intervening rollout
could replay it. The placement contract fail-closes a PRESENT era/generation
pair that is malformed, incomplete, out of bounds, or internally inconsistent
rather than coercing it to era 0; only the pre-contract absence of BOTH fields
may enter cleanup and stamp era 1. An initial install, and any contract
installed before this field existed, therefore yields NO proof generation, which
is fail-closed: the settled host DaemonSet refuses to render until an explicit
cleanup/finalize pair has stamped one.

Both DaemonSets include this SAME helper so the ambient preflight and the
node-agent's registry-synchronization publication can never disagree about
which era a proof belongs to.
*/}}
{{/*
Render the injector mutating webhook namespaceSelector. User-provided
matchExpressions are preserved, but the release namespace is always appended so
an override of injector.namespaceSelector cannot re-enable admission on the
chart's own namespace (issue #4155 bootstrap deadlock).
*/}}
{{- define "ferrum-mesh.renderInjectorWebhookNamespaceSelector" -}}
{{- $user := .namespaceSelector | default dict -}}
{{- $releaseNs := .Release.Namespace -}}
{{- $exprs := $user.matchExpressions | default list -}}
{{- $hasReleaseExclusion := false -}}
{{- range $exprs -}}
{{- if and (eq .key "kubernetes.io/metadata.name") (eq .operator "NotIn") (has $releaseNs .values) -}}
{{- $hasReleaseExclusion = true -}}
{{- end -}}
{{- end -}}
{{- if not $hasReleaseExclusion -}}
{{- $exprs = append $exprs (dict "key" "kubernetes.io/metadata.name" "operator" "NotIn" "values" (list $releaseNs)) -}}
{{- end -}}
{{- $selector := dict "matchExpressions" $exprs -}}
{{- if $user.matchLabels -}}
{{- $_ := set $selector "matchLabels" $user.matchLabels -}}
{{- end -}}
{{- $selector | toYaml -}}
{{- end -}}

{{- define "ferrum-mesh.ambientUdpNodeProofGeneration" -}}
{{- $env := default dict .Values.ambient.env -}}
{{- $topology := replace "-" "_" (lower (trim (toString (index $env "FERRUM_MESH_TOPOLOGY")))) -}}
{{- $result := "" -}}
{{- if and .Values.ambient.enabled (eq $topology "ambient") .Release.IsUpgrade -}}
{{- $contractName := printf "ferrum-mesh-udp-placement-%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- $installed := lookup "v1" "ConfigMap" .Release.Namespace $contractName -}}
{{- if $installed -}}
{{- $data := default dict $installed.data -}}
{{- $result = trim (toString (default "" (index $data "nodeProofGeneration"))) -}}
{{- end -}}
{{- end -}}
{{- $result -}}
{{- end -}}

{{/*
Render hostname spread constraints for HA Deployments (replicas >= 2). When
topologySpreadConstraints is unset, apply a chart default across nodes. An
explicit empty slice disables spread even at higher replica counts.
*/}}
{{- define "ferrum-mesh.renderTopologySpreadConstraints" -}}
{{- $replicas := .replicas | int -}}
{{- if ge $replicas 2 -}}
{{- if kindIs "slice" .constraints -}}
{{- if gt (len .constraints) 0 }}
      topologySpreadConstraints:
{{- toYaml .constraints | nindent 8 }}
{{- end -}}
{{- else }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: {{ .selectorName }}
              app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render a PodDisruptionBudget when the workload is enabled, podDisruptionBudget
is enabled globally, and replicas >= 2. Single-replica workloads skip PDB so
minAvailable: 1 cannot block voluntary evictions during node drains.
*/}}
{{- define "ferrum-mesh.renderPodDisruptionBudget" -}}
{{- $root := .root -}}
{{- $pdb := $root.Values.podDisruptionBudget | default dict -}}
{{- $replicas := .replicas | int -}}
{{- if and .componentEnabled ($pdb.enabled | default false) (ge $replicas 2) -}}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ .name }}
  namespace: {{ $root.Release.Namespace }}
  labels:
    app.kubernetes.io/name: {{ .selectorName }}
    app.kubernetes.io/instance: {{ $root.Release.Name }}
spec:
  {{- if not (kindIs "invalid" $pdb.minAvailable) }}
  minAvailable: {{ $pdb.minAvailable }}
  {{- else if not (kindIs "invalid" $pdb.maxUnavailable) }}
  maxUnavailable: {{ $pdb.maxUnavailable }}
  {{- end }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ .selectorName }}
      app.kubernetes.io/instance: {{ $root.Release.Name }}
{{- end -}}
{{- end -}}

{{/*
True when the bind is loopback (or empty, which the binary defaults to
127.0.0.1). Wildcards 0.0.0.0 / :: are not loopback.

Decided from the PARSED address rather than a prefix string, so every spelling
the runtime's `IpAddr::is_loopback()` accepts is classified the same way here:
any address in 127.0.0.0/8, `::1` in any valid contraction, and the IPv4-mapped
form of a 127/8 address (which the runtime canonicalizes to IPv4).
*/}}
{{- define "ferrum-mesh.isLoopbackBind" -}}
{{- $bind := . | toString | trim | trimPrefix "[" | trimSuffix "]" -}}
{{- $v4 := include "ferrum-mesh.ipv4ToInt" $bind -}}
{{- if eq $v4 "" -}}{{- $v4 = include "ferrum-mesh.ipv4MappedToInt" $bind -}}{{- end -}}
{{- if eq $bind "" -}}
true
{{- else if ne $v4 "" -}}
{{- if eq (div ($v4 | int64) 16777216 | int) 127 -}}true{{- end -}}
{{- else if eq (include "ferrum-mesh.ipv6Hextets" $bind) "0,0,0,0,0,0,0,1" -}}
true
{{- end -}}
{{- end -}}

{{/*
True when a secret-source dict has value, valueFrom, or existingSecret.name.
*/}}
{{- define "ferrum-mesh.sourceConfigured" -}}
{{- $source := . | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- if or $source.value $source.valueFrom $existing.name -}}
true
{{- end -}}
{{- end -}}

{{/*
0 or 1 of value / existingSecret.name / valueFrom. More than one fails.
*/}}
{{- define "ferrum-mesh.validateOptionalSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if gt $count 1 -}}
{{- fail (printf "%s must set at most one of value, existingSecret.name, or valueFrom" $label) -}}
{{- end -}}
{{- end -}}

{{/*
Parse a boolean env override the same way `EnvConfig`'s bool parser does:
trim, lowercase, accept true/false/1/0 only. Returns canonical "true" or
"false". Dict: field (for value-redacted diagnostics), value.
*/}}
{{- define "ferrum-mesh.parseEnvBool" -}}
{{- $field := .field -}}
{{- $lower := lower (trim (toString (.value | default ""))) -}}
{{- if not (has $lower (list "true" "false" "1" "0")) -}}
{{- fail (printf "%s is not a valid boolean; expected true, false, 1, or 0" $field) -}}
{{- end -}}
{{- if has $lower (list "true" "1") -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Resolve the admin listener for a serving component. First-class
`<component>.admin` is the chart-managed source; an explicit env map entry
still wins so existing ambient.env.FERRUM_ADMIN_* collision tests and live
suites keep working. All FOUR admin keys are resolved here, because
`ferrum-mesh.adminEnv` renders exclusively from this result and every workload
env loop filters those keys out. Returns YAML dict: port, bind, probeHost,
allowInsecureHttp, allowInsecureHttpFromEnv, allowedCidrs.
*/}}
{{- define "ferrum-mesh.resolveComponentAdmin" -}}
{{- $env := .env | default dict -}}
{{- $admin := .admin | default dict -}}
{{- $port := "9000" -}}
{{- if not (kindIs "invalid" $admin.httpPort) -}}
{{- $port = toString $admin.httpPort -}}
{{- end -}}
{{- if hasKey $env "FERRUM_ADMIN_HTTP_PORT" -}}
{{- $port = toString (index $env "FERRUM_ADMIN_HTTP_PORT") -}}
{{- end -}}
{{- $bind := "127.0.0.1" -}}
{{- if $admin.bindAddress -}}
{{- $bind = toString $admin.bindAddress -}}
{{- end -}}
{{- if hasKey $env "FERRUM_ADMIN_BIND_ADDRESS" -}}
{{- $bind = toString (index $env "FERRUM_ADMIN_BIND_ADDRESS") -}}
{{- end -}}
{{- /* The runtime parses FERRUM_ADMIN_BIND_ADDRESS as a bare IP literal, so a
       balanced bracketed IPv6 literal is normalized here rather than rendered
       into the env. A MISMATCHED bracket is left intact so
       `ferrum-mesh.validateAdminBind` can reject it with a precise message. */ -}}
{{- if and (hasPrefix "[" $bind) (hasSuffix "]" $bind) -}}
{{- $bind = $bind | trimPrefix "[" | trimSuffix "]" -}}
{{- end -}}
{{- /* The allowlist and the insecure opt-in are resolved from the env map for
       the same reason the port and the bind are: `ferrum-mesh.adminEnv` is the
       SOLE renderer of all four keys, so a value that is not resolved here is
       dropped from the rendered PodSpec entirely. Silently losing
       FERRUM_ADMIN_ALLOWED_CIDRS would leave a non-loopback plaintext admin
       listener with no allowlist. */ -}}
{{- $allowInsecureHttp := $admin.allowInsecureHttp | default false -}}
{{- $allowInsecureHttpFromEnv := false -}}
{{- if hasKey $env "FERRUM_ALLOW_INSECURE_ADMIN_HTTP" -}}
{{- $boolField := "FERRUM_ALLOW_INSECURE_ADMIN_HTTP" -}}
{{- if .component -}}
{{- $boolField = printf "%s.env.FERRUM_ALLOW_INSECURE_ADMIN_HTTP" .component -}}
{{- end -}}
{{- $canonical := include "ferrum-mesh.parseEnvBool" (dict "field" $boolField "value" (index $env "FERRUM_ALLOW_INSECURE_ADMIN_HTTP")) -}}
{{- $allowInsecureHttp = eq $canonical "true" -}}
{{- $allowInsecureHttpFromEnv = true -}}
{{- end -}}
{{- $allowedCidrs := $admin.allowedCidrs | default "" -}}
{{- if hasKey $env "FERRUM_ADMIN_ALLOWED_CIDRS" -}}
{{- $allowedCidrs = toString (index $env "FERRUM_ADMIN_ALLOWED_CIDRS") -}}
{{- end -}}
{{- dict "port" $port "bind" $bind "probeHost" (include "ferrum-mesh.adminProbeHost" $bind) "allowInsecureHttp" $allowInsecureHttp "allowInsecureHttpFromEnv" $allowInsecureHttpFromEnv "allowedCidrs" $allowedCidrs | toYaml -}}
{{- end -}}

{{/*
Chart-managed admin env for a serving component.

This helper is the ONLY renderer of the four admin env keys: every workload
template that includes it also filters them out of its own `env` map loop (the
ambient DaemonSet included), so an explicit `<workload>.env.FERRUM_ADMIN_*`
entry reaches the container through `ferrum-mesh.resolveComponentAdmin` — which
also normalizes a bracketed IPv6 bind — instead of being rendered twice or, if
this helper skipped it, not at all.
*/}}
{{- define "ferrum-mesh.adminEnv" -}}
{{- $resolved := .resolved -}}
- name: FERRUM_ADMIN_HTTP_PORT
  value: {{ $resolved.port | quote }}
- name: FERRUM_ADMIN_BIND_ADDRESS
  value: {{ $resolved.bind | quote }}
{{- if $resolved.allowInsecureHttpFromEnv }}
- name: FERRUM_ALLOW_INSECURE_ADMIN_HTTP
  value: {{ ternary "true" "false" $resolved.allowInsecureHttp | quote }}
{{- else if $resolved.allowInsecureHttp }}
- name: FERRUM_ALLOW_INSECURE_ADMIN_HTTP
  value: "true"
{{- end }}
{{- $cidrs := trim ($resolved.allowedCidrs | toString) -}}
{{- if $cidrs }}
- name: FERRUM_ADMIN_ALLOWED_CIDRS
  value: {{ $cidrs | quote }}
{{- end }}
{{- end -}}

{{/*
Shutdown drain env. Presence, not truthiness: shutdownDrainSeconds=0 must
still emit FERRUM_SHUTDOWN_DRAIN_SECONDS=0 or the binary falls back to 30s.
*/}}
{{- define "ferrum-mesh.shutdownEnv" -}}
{{- if not (kindIs "invalid" .shutdownDrainSeconds) }}
- name: FERRUM_SHUTDOWN_DRAIN_SECONDS
  value: {{ .shutdownDrainSeconds | quote }}
{{- end }}
{{- if not (kindIs "invalid" .shutdownPreDrainSeconds) }}
- name: FERRUM_SHUTDOWN_PREDRAIN_SECONDS
  value: {{ .shutdownPreDrainSeconds | quote }}
{{- end }}
{{- end -}}

{{/*
Native SleepAction preStop (Kubernetes 1.29+). Distroless has no shell.
Omitted when shutdownPreStopSeconds is 0.
*/}}
{{- define "ferrum-mesh.preStopLifecycle" -}}
{{- $preStop := int (.shutdownPreStopSeconds | default 0) -}}
{{- if gt $preStop 0 }}
lifecycle:
  preStop:
    sleep:
      seconds: {{ $preStop }}
{{- end -}}
{{- end -}}

{{/*
Metrics auth env. Only when observability.enabled. Bearer token is never
logged; inline value is for lab installs only.
*/}}
{{- define "ferrum-mesh.metricsEnv" -}}
{{- $obs := .Values.observability | default dict -}}
{{- if $obs.enabled }}
{{- $metrics := $obs.metrics | default dict -}}
{{- if $metrics.allowedCidrs }}
- name: FERRUM_METRICS_ALLOWED_CIDRS
  value: {{ $metrics.allowedCidrs | quote }}
{{- end }}
{{- if include "ferrum-mesh.sourceConfigured" ($metrics.bearerToken | default dict) }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_METRICS_BEARER_TOKEN" "source" ($metrics.bearerToken | default dict) "defaultKey" "metrics-bearer-token") }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Full additive post-SIGTERM shutdown budget (docs/graceful_shutdown.md):
  drain + 6s transport pool + 5s background + clamp(drain,5,60)s audit
  + 2s observability + 5s finalizer slack.
preStop and preDrain are billed to the same terminationGracePeriodSeconds
clock. Dict: root, component (string), values (component values).
*/}}
{{- define "ferrum-mesh.validateShutdown" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $v := .values | default dict -}}
{{- $drain := $v.shutdownDrainSeconds -}}
{{- $effectiveDrain := 30 -}}
{{- if not (kindIs "invalid" $drain) -}}{{- $effectiveDrain = int $drain -}}{{- end -}}
{{- $auditBudget := $effectiveDrain -}}
{{- if lt $auditBudget 5 -}}{{- $auditBudget = 5 -}}{{- end -}}
{{- if gt $auditBudget 60 -}}{{- $auditBudget = 60 -}}{{- end -}}
{{- $shutdownBudget := add $effectiveDrain (add 6 (add 5 (add $auditBudget (add 2 5)))) -}}
{{- $preStop := int ($v.shutdownPreStopSeconds | default 0) -}}
{{- $preDrain := int ($v.shutdownPreDrainSeconds | default 0) -}}
{{- $minGrace := add $preStop (add $preDrain $shutdownBudget) -}}
{{- $grace := $v.terminationGracePeriodSeconds -}}
{{- if kindIs "invalid" $grace -}}
{{- fail (printf "%s.terminationGracePeriodSeconds is required when the workload is enabled (minimum %d = preStop %ds + preDrain %ds + shutdown budget %ds)" $component $minGrace $preStop $preDrain $shutdownBudget) -}}
{{- end -}}
{{- if lt (int $grace) $minGrace -}}
{{- fail (printf "%s.terminationGracePeriodSeconds (%d) must be at least %d (preStop %ds + preDrain %ds + shutdown budget %ds, where the shutdown budget is drain %ds + transport pool 6s + background 5s + audit %ds + observability 2s + finalizer slack 5s); a null shutdownDrainSeconds uses the binary's 30s default" $component (int $grace) $minGrace $preStop $preDrain $shutdownBudget $effectiveDrain $auditBudget) -}}
{{- end -}}
{{- if gt $preStop 0 -}}
{{- $major := atoi (regexReplaceAll "[^0-9].*$" ($root.Capabilities.KubeVersion.Major | toString) "") -}}
{{- $minor := atoi (regexReplaceAll "[^0-9].*$" ($root.Capabilities.KubeVersion.Minor | toString) "") -}}
{{- /* helm template without --kube-version advertises 1.20.0. That sentinel is
     not a real cluster; skip so GitOps/client renders still emit the 1.29+
     SleepAction default. --kube-version 1.28.0 and real <1.29 clusters fail. */ -}}
{{- $helmTemplateDefault := and (eq $major 1) (eq $minor 20) -}}
{{- $sleepUnsupported := and (not $helmTemplateDefault) (or (lt $major 1) (and (eq $major 1) (lt $minor 29))) -}}
{{- if $sleepUnsupported -}}
{{- $kube := $root.Capabilities.KubeVersion.Version | default (printf "v%d.%d" $major $minor) -}}
{{- fail (printf "%s.shutdownPreStopSeconds=%d renders lifecycle.preStop.sleep (SleepAction), which requires Kubernetes 1.29+ (GA in 1.30). This cluster reports %s. Set %s.shutdownPreStopSeconds=0 to omit the hook and raise %s.shutdownPreDrainSeconds to at least readiness failureThreshold × periodSeconds so kube-proxy endpoint removal can finish after SIGTERM while /health already reports not-ready." $component $preStop $kube $component $component) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateServingShutdowns" -}}
{{- if .Values.controlPlane.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "controlPlane" "values" .Values.controlPlane) -}}
{{- end -}}
{{- if .Values.ca.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "ca" "values" .Values.ca) -}}
{{- end -}}
{{- if .Values.eastWest.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "eastWest" "values" .Values.eastWest) -}}
{{- end -}}
{{- if .Values.ambient.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "ambient" "values" .Values.ambient) -}}
{{- end -}}
{{- end -}}

{{/*
Reserved chart-managed env names that must not appear in a workload env map.
*/}}
{{- define "ferrum-mesh.failReservedEnv" -}}
{{- $label := .label -}}
{{- $env := .env | default dict -}}
{{- range $name := .names -}}
{{- if hasKey $env $name -}}
{{- fail (printf "%s.%s is chart-managed; use the matching first-class value instead of overriding the rendered environment" $label $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.shutdownAndMetricsReserved" -}}
FERRUM_SHUTDOWN_DRAIN_SECONDS
FERRUM_SHUTDOWN_PREDRAIN_SECONDS
FERRUM_METRICS_BEARER_TOKEN
FERRUM_METRICS_ALLOWED_CIDRS
{{- end -}}

{{/*
Strictly validate one comma-separated allowlist against `CidrSet::parse_strict`.
An empty string is "no allowlist" and is accepted; anything non-empty must parse
entry-for-entry, or the pod renders cleanly and then CrashLoops at startup.
Dict: label (values path used in the message), cidrs.
*/}}
{{- define "ferrum-mesh.validateCidrList" -}}
{{- $label := .label -}}
{{- $cidrs := trim (.cidrs | default "" | toString) -}}
{{- if $cidrs -}}
{{- range $raw := splitList "," $cidrs -}}
{{- $entry := trim $raw -}}
{{- if or (contains "[" $entry) (contains "]" $entry) -}}
{{- fail (printf "%s entry %q uses bracketed IPv6 syntax, but the runtime requires bare IPv6 addresses/CIDRs (for example fd00::/8 or ::1/128)" $label $entry) -}}
{{- end -}}
{{- if not (include "ferrum-mesh.validAdminCidrEntry" $entry) -}}
{{- $display := $entry | default "<empty>" -}}
{{- fail (printf "%s entry %q is not a valid IP address or CIDR; expected forms such as 10.0.0.0/8, 192.168.1.1, ::1, or fd00::/8" $label $display) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
`EnvConfig::validate()` rejects any FERRUM_ADMIN_BIND_ADDRESS that is not an IP
literal, so a hostname bind renders cleanly and then exits at boot. Reject it at
render with the IP to use instead. Dict: component, bind.
*/}}
{{- define "ferrum-mesh.validateAdminBind" -}}
{{- $component := .component -}}
{{- $bind := .bind | default "" | toString -}}
{{- $open := hasPrefix "[" $bind -}}
{{- $close := hasSuffix "]" $bind -}}
{{- if ne $open $close -}}
{{- fail (printf "%s.admin.bindAddress=%q has mismatched IPv6 brackets; use a bare IPv6 literal such as :: or ::1" $component $bind) -}}
{{- end -}}
{{- $host := $bind | trimPrefix "[" | trimSuffix "]" -}}
{{- if and $open (not (contains ":" $host)) -}}
{{- fail (printf "%s.admin.bindAddress=%q brackets a non-IPv6 address; IPv4 bind addresses must use bare form such as 127.0.0.1 or 0.0.0.0" $component $bind) -}}
{{- end -}}
{{- if eq (lower $host) "localhost" -}}
{{- fail (printf "%s.admin.bindAddress=localhost is rejected: the binary requires FERRUM_ADMIN_BIND_ADDRESS to be an IP literal and exits otherwise. Use 127.0.0.1 (or ::1) for the loopback default, or 0.0.0.0/:: to expose admin." $component) -}}
{{- end -}}
{{- if and $host (not (include "ferrum-mesh.isIpLiteral" $host)) -}}
{{- fail (printf "%s.admin.bindAddress=%q is not an IP literal: the binary requires FERRUM_ADMIN_BIND_ADDRESS to parse as an IP address (e.g. 127.0.0.1, ::1, 0.0.0.0, ::) and exits otherwise. Use an IP literal, not a hostname." $component $bind) -}}
{{- end -}}
{{- end -}}

{{/*
Component admin validation.

1. The bind must be an IP literal and the allowlist must parse strictly, in
   EVERY component — the runtime parses both the same way regardless of mode.
2. CP/CA (`hardFail`) additionally refuse a non-loopback PLAINTEXT admin bind
   without an EFFECTIVE allowlist or the explicit insecure opt-in. "Effective"
   means it does not cover a whole IP family: `0.0.0.0/0`, an IPv4-mapped `/96`,
   and a full-coverage union all restrict nothing, so none of them count as
   plaintext protection.
3. Whenever a computed exec probe is active AND an allowlist is set, the exact
   source address the admin TCP accept loop observes must be covered. Substring
   matching is not enough: an IPv6 wildcard bind dials `::1` and is dropped by an
   IPv4-only allowlist (and vice versa), which the kubelet sees as a restart
   loop, not a render error.

Dict: component, resolved, hardFail, probes.
*/}}
{{- define "ferrum-mesh.validatePlaintextAdmin" -}}
{{- $component := .component -}}
{{- $resolved := .resolved -}}
{{- $hardFail := .hardFail -}}
{{- $probes := .probes | default dict -}}
{{- $cidrs := trim ($resolved.allowedCidrs | default "" | toString) -}}
{{- include "ferrum-mesh.validateAdminBind" (dict "component" $component "bind" $resolved.bind) -}}
{{- include "ferrum-mesh.validateCidrList" (dict "label" (printf "%s.admin.allowedCidrs" $component) "cidrs" $cidrs) -}}
{{- $port := toString $resolved.port -}}
{{- if ne $port "0" -}}
{{- $loopback := include "ferrum-mesh.isLoopbackBind" $resolved.bind -}}
{{- if and (not $loopback) $hardFail -}}
{{- $permitsAll := include "ferrum-mesh.adminAllowlistPermitsAll" $cidrs -}}
{{- $effective := and $cidrs (not $permitsAll) -}}
{{- if not (or $effective $resolved.allowInsecureHttp) -}}
{{- if $permitsAll -}}
{{- fail (printf "%s.admin.allowedCidrs permits every address in an IP family (for example via /0, an IPv4-mapped /96, or a full-coverage CIDR union), which does not restrict the non-loopback plaintext admin listener on bind %q. Use a narrower allowlist, keep the loopback default, or set %s.admin.allowInsecureHttp=true (insecure development only)." $component $resolved.bind $component) -}}
{{- end -}}
{{- fail (printf "%s admin bind %q is a non-loopback plaintext listener. Set %s.admin.allowedCidrs to a narrower allowlist, set %s.admin.allowInsecureHttp=true (insecure development only), or keep the loopback default. Control-plane/CA mode refuses to start otherwise." $component $resolved.bind $component $component) -}}
{{- end -}}
{{- end -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $computedLive := and (or ($startup.enabled | default false) ($liveness.enabled | default false)) (not ($liveness.override | default dict)) -}}
{{- $computedReady := and ($readiness.enabled | default false) (not ($readiness.override | default dict)) -}}
{{- if and $cidrs (or $computedLive $computedReady) -}}
{{- $probeHost := $resolved.probeHost | default (include "ferrum-mesh.adminProbeHost" $resolved.bind) -}}
{{- $probeSource := include "ferrum-mesh.probeSource" $probeHost -}}
{{- if not (include "ferrum-mesh.adminAllowlistContainsIp" (dict "ip" $probeSource "allowedCidrs" $cidrs)) -}}
{{- $probeCidr := ternary (printf "%s/128" $probeSource) (printf "%s/32" $probeSource) (contains ":" $probeSource) -}}
{{- fail (printf "%s.admin.allowedCidrs must include %s (or bare %s) while the computed exec probes are enabled; they dial admin host %s from source %s and the admin TCP allowlist otherwise drops the in-pod health checks. Add the exact probe source (or a covering CIDR), or override/disable every computed probe handler." $component $probeCidr $probeSource $probeHost $probeSource) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Every ENABLED computed probe must have a usable handler.

`ferrum-mesh.renderProbes` skips a probe whose handler is empty, so an admin
HTTP port of 0 (or any other configuration that yields no computed handler)
silently drops readiness — the workload then never leaves the Service endpoint
set on drain. Checking the pair (`not live` AND `not ready`) is not enough: one
custom override satisfies it while the other enabled probe is still handler-less.

Dict: component, probes, liveHandler, readyHandler, startupHandler (optional;
falls back to liveHandler exactly as renderProbes does).
*/}}
{{- define "ferrum-mesh.validateComputedProbeHandlers" -}}
{{- $component := .component -}}
{{- $probes := .probes | default dict -}}
{{- $liveHandler := .liveHandler | default dict -}}
{{- $readyHandler := .readyHandler | default dict -}}
{{- $startupHandler := .startupHandler | default dict -}}
{{- if not $startupHandler -}}{{- $startupHandler = $liveHandler -}}{{- end -}}
{{- $hint := printf "set %s.admin.httpPort to a non-zero port, supply an explicit %s.probes.<probe>.override handler, or disable that probe with %s.probes.<probe>.enabled=false" $component $component $component -}}
{{- if and ((($probes.startup | default dict).enabled) | default false) (not $startupHandler) -}}
{{- fail (printf "%s.probes.startup is enabled but no handler can be computed for it, so the rendered PodSpec would silently omit the probe: %s" $component $hint) -}}
{{- end -}}
{{- if and ((($probes.liveness | default dict).enabled) | default false) (not $liveHandler) -}}
{{- fail (printf "%s.probes.liveness is enabled but no handler can be computed for it, so the rendered PodSpec would silently omit the probe: %s" $component $hint) -}}
{{- end -}}
{{- if and ((($probes.readiness | default dict).enabled) | default false) (not $readyHandler) -}}
{{- fail (printf "%s.probes.readiness is enabled but no handler can be computed for it, so the rendered PodSpec would silently omit drain-aware readiness and the workload would stay in the Service endpoint set through shutdown: %s" $component $hint) -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateObservability" -}}
{{- $obs := .Values.observability | default dict -}}
{{- if not $obs.enabled -}}
{{- else -}}
{{- $metrics := $obs.metrics | default dict -}}
{{- $alerts := $obs.alerts | default dict -}}
{{- $sm := $metrics.serviceMonitor | default dict -}}
{{- $pm := $metrics.podMonitor | default dict -}}
{{- /* Sprig `false | default true` treats false as empty. Presence: anything
     other than the string "false" keeps the observability default of on. */ -}}
{{- $smOn := ne ($sm.enabled | toString) "false" -}}
{{- $pmOn := ne ($pm.enabled | toString) "false" -}}
{{- $alertsOn := ne ($alerts.enabled | toString) "false" -}}
{{- $monitoringOn := or $smOn $pmOn -}}
{{- $allowedCidrs := trim ($metrics.allowedCidrs | default "") -}}
{{- /* The runtime parses FERRUM_METRICS_ALLOWED_CIDRS with the same strict
     CidrSet parser as the admin allowlist, so validate it identically instead
     of accepting anything that merely contains a dot or a colon. */ -}}
{{- include "ferrum-mesh.validateCidrList" (dict "label" "observability.metrics.allowedCidrs" "cidrs" $allowedCidrs) -}}
{{- $bearer := $metrics.bearerToken | default dict -}}
{{- include "ferrum-mesh.validateOptionalSource" (dict "label" "observability.metrics.bearerToken" "source" $bearer) -}}
{{- $hasBearer := include "ferrum-mesh.sourceConfigured" $bearer -}}
{{- if and (or $alertsOn $monitoringOn) (not $allowedCidrs) (not $hasBearer) -}}
{{- fail "observability.alerts or ServiceMonitor/PodMonitor is enabled without a scrape credential: set observability.metrics.bearerToken (value, existingSecret.name, or valueFrom) or a non-empty observability.metrics.allowedCidrs so /metrics scrapes can be authorized and alerts are not permanently no-data" -}}
{{- end -}}
{{- $bearerSecret := ($bearer.existingSecret | default dict).name | default "" -}}
{{- if and $monitoringOn (not $allowedCidrs) (not $bearerSecret) $hasBearer -}}
{{- fail "observability ServiceMonitor/PodMonitor without metrics.allowedCidrs requires observability.metrics.bearerToken.existingSecret.name so the monitor can attach Bearer authorization (inline bearerToken.value wires the pod env only — create the Secret out-of-band)" -}}
{{- end -}}
{{- $cpAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "component" "controlPlane" "env" (.Values.controlPlane.env | default dict) "admin" (.Values.controlPlane.admin | default dict)) | fromYaml -}}
{{- $caAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "component" "ca" "env" (.Values.ca.env | default dict) "admin" (.Values.ca.admin | default dict)) | fromYaml -}}
{{- $ewAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "component" "eastWest" "env" (.Values.eastWest.env | default dict) "admin" (.Values.eastWest.admin | default dict)) | fromYaml -}}
{{- $ambAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "component" "ambient" "env" (.Values.ambient.env | default dict) "admin" (.Values.ambient.admin | default dict)) | fromYaml -}}
{{- if and $smOn .Values.controlPlane.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $cpAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with controlPlane.enabled=true requires a non-loopback controlPlane.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $cpAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with controlPlane.enabled=true requires a non-zero controlPlane.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $smOn .Values.ca.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $caAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with ca.enabled=true requires a non-loopback ca.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $caAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with ca.enabled=true requires a non-zero ca.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $smOn .Values.eastWest.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $ewAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with eastWest.enabled=true requires a non-loopback eastWest.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $ewAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with eastWest.enabled=true requires a non-zero eastWest.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $pmOn .Values.ambient.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $ambAdmin.bind -}}
{{- fail "observability.metrics.podMonitor.enabled=true with ambient.enabled=true requires a non-loopback ambient.admin.bindAddress (e.g. 0.0.0.0); hostNetwork loopback is not reachable from Prometheus" -}}
{{- end -}}
{{- if eq (toString $ambAdmin.port) "0" -}}
{{- fail "observability.metrics.podMonitor.enabled=true with ambient.enabled=true requires a non-zero ambient.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $pmOn .Values.nodeAgent.enabled (.Values.nodeAgent.admin.enabled | default true) -}}
{{- $naBind := .Values.nodeAgent.admin.bindAddress | default "127.0.0.1" -}}
{{- $naPort := toString (.Values.nodeAgent.admin.port | default "19090") -}}
{{- if include "ferrum-mesh.isLoopbackBind" $naBind -}}
{{- fail "observability.metrics.podMonitor.enabled=true with nodeAgent.enabled=true requires a non-loopback nodeAgent.admin.bindAddress (e.g. 0.0.0.0); hostNetwork loopback is not reachable from Prometheus" -}}
{{- end -}}
{{- if eq $naPort "0" -}}
{{- fail "observability.metrics.podMonitor.enabled=true with nodeAgent.enabled=true requires a non-zero nodeAgent.admin.port so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Sane non-empty resource requests. Empty resources{} would restore BestEffort.
*/}}
{{- define "ferrum-mesh.validateResources" -}}
{{- $component := .component -}}
{{- $res := .resources | default dict -}}
{{- $req := $res.requests | default dict -}}
{{- if or (not $req.cpu) (not $req.memory) -}}
{{- fail (printf "%s.resources.requests.cpu and %s.resources.requests.memory must be non-empty so the mesh workload is not BestEffort QoS" $component $component) -}}
{{- end -}}
{{- end -}}

{{/*
Normalize one Linux capability name. Rejects empty strings, surrounding
whitespace, and anything outside `^(CAP_)?[A-Z][A-Z0-9_]*$` (YAML punctuation
included). Returns the unprefixed uppercase form (`NET_ADMIN`, `ALL`).
Callers that render capabilities.add must still reject the ALL token.
*/}}
{{- define "ferrum-mesh.normalizedLinuxCapability" -}}
{{- $raw := . | toString -}}
{{- $trimmed := trim $raw -}}
{{- if or (ne $raw $trimmed) (eq $trimmed "") (not (regexMatch "^(CAP_)?[A-Z][A-Z0-9_]*$" $trimmed)) -}}
{{- fail (printf "ambient.securityContext.capabilities entry %q is not a Linux capability name; use names such as NET_ADMIN or ALL (optional CAP_ prefix). Empty strings and YAML punctuation are rejected." $raw) -}}
{{- end -}}
{{- upper (trimPrefix "CAP_" (upper $trimmed)) -}}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Strict IP / CIDR primitives, ported from charts/ferrum-gateway/templates/_helpers.tpl
so the mesh chart applies the SAME accept/reject decision the runtime does
(`CidrSet::parse_strict` and `IpAddr`/`IpNet` parsing in src/config/). A weaker
approximation renders cleanly and then CrashLoops (or has the admin accept loop
silently drop the in-pod exec probes), which is exactly what these mirror.
Keep them byte-comparable with the gateway copies.
--------------------------------------------------------------------------- */}}

{{/* Render a non-negative int64 as a fixed-width binary string. Widths used by
     this chart are 16 (one IPv6 hextet) and 32 (one IPv4 address). */}}
{{- define "ferrum-mesh.unsignedBinaryBits" -}}
{{- $value := .value | int64 -}}
{{- $width := .width | int -}}
{{- $divisor := 1 | int64 -}}
{{- range until (sub $width 1 | int) -}}{{- $divisor = mul $divisor 2 -}}{{- end -}}
{{- $bits := "" -}}
{{- range until $width -}}
{{- if ge $value $divisor -}}
{{- $bits = printf "%s1" $bits -}}
{{- $value = sub $value $divisor -}}
{{- else -}}
{{- $bits = printf "%s0" $bits -}}
{{- end -}}
{{- if gt $divisor 1 -}}{{- $divisor = div $divisor 2 -}}{{- end -}}
{{- end -}}
{{- $bits -}}
{{- end -}}

{{- define "ferrum-mesh.ipv4Bits" -}}
{{- include "ferrum-mesh.unsignedBinaryBits" (dict "value" (. | int64) "width" 32) -}}
{{- end -}}

{{- define "ferrum-mesh.ipv6Bits" -}}
{{- $hextets := include "ferrum-mesh.ipv6Hextets" (. | toString) -}}
{{- $bits := "" -}}
{{- if $hextets -}}
{{- range $part := splitList "," $hextets -}}
{{- $bits = printf "%s%s" $bits (include "ferrum-mesh.unsignedBinaryBits" (dict "value" ($part | int64) "width" 16)) -}}
{{- end -}}
{{- end -}}
{{- $bits -}}
{{- end -}}

{{/* Source address the admin listener observes for the computed exec probe.
     Linux selects 127.0.0.1 when connecting to any concrete 127/8 destination;
     other concrete/wildcard probe hosts use the same local address they dial.
     IPv4-mapped IPv6 destinations are canonicalized to IPv4 first (matching the
     runtime), so `::ffff:127.0.0.2` is a 127/8 dial and the observed source is
     `127.0.0.1`, not the mapped destination text. Ordinary IPv6 is unchanged.
     Input is the already-resolved probe host (`ferrum-mesh.adminProbeHost`),
     because the mesh chart resolves admin per component rather than from one
     chart-wide `.Values.admin`. */}}
{{- define "ferrum-mesh.probeSource" -}}
{{- $host := . | toString | trimPrefix "[" | trimSuffix "]" -}}
{{- $v4 := include "ferrum-mesh.ipv4ToInt" $host -}}
{{- if eq $v4 "" -}}{{- $v4 = include "ferrum-mesh.ipv4MappedToInt" $host -}}{{- end -}}
{{- if ne $v4 "" -}}
{{- $int := $v4 | int64 -}}
{{- if eq (div $int 16777216 | int) 127 -}}127.0.0.1
{{- else -}}{{ include "ferrum-mesh.ipv4IntToDotted" $int }}
{{- end -}}
{{- else -}}{{ $host }}
{{- end -}}
{{- end -}}

{{/* "true" when the value parses as a strict IPv4 or IPv6 literal, else "".
     Mirrors the runtime's IpAddr parsing: IPv4 octets are canonical decimal and
     IPv6 is fully expanded/validated, including an optional embedded IPv4 tail. */}}
{{- define "ferrum-mesh.isIpLiteral" -}}
{{- $v := . | toString -}}
{{- $octet := "(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := printf "^%s\\.%s\\.%s\\.%s$" $octet $octet $octet $octet -}}
{{- if regexMatch $ipv4 $v -}}true
{{- else if and (contains ":" $v) (include "ferrum-mesh.ipv6Hextets" $v) -}}true
{{- end -}}
{{- end -}}

{{/* Convert a validated IPv4 literal to its unsigned 32-bit integer value. */}}
{{- define "ferrum-mesh.ipv4ToInt" -}}
{{- $v := . | toString -}}
{{- if and (include "ferrum-mesh.isIpLiteral" $v) (not (contains ":" $v)) -}}
{{- $parts := splitList "." $v -}}
{{- add (mul (index $parts 0 | int64) 16777216) (mul (index $parts 1 | int64) 65536) (mul (index $parts 2 | int64) 256) (index $parts 3 | int64) -}}
{{- end -}}
{{- end -}}

{{/* Convert an unsigned 32-bit IPv4 integer back to dotted-decimal. */}}
{{- define "ferrum-mesh.ipv4IntToDotted" -}}
{{- $v := . | int64 -}}
{{- printf "%d.%d.%d.%d" (div $v 16777216) (mod (div $v 65536) 256) (mod (div $v 256) 256) (mod $v 256) -}}
{{- end -}}

{{/* Convert one validated IPv6 hextet to an integer. Helm has no base-16 atoi. */}}
{{- define "ferrum-mesh.hexToInt" -}}
{{- $digits := dict "0" 0 "1" 1 "2" 2 "3" 3 "4" 4 "5" 5 "6" 6 "7" 7 "8" 8 "9" 9 "a" 10 "b" 11 "c" 12 "d" 13 "e" 14 "f" 15 -}}
{{- $value := 0 -}}
{{- range $digit := regexFindAll "." (lower (. | toString)) -1 -}}
{{- $value = add (mul $value 16) (get $digits $digit) -}}
{{- end -}}
{{- $value -}}
{{- end -}}

{{/* Expand an IPv6 literal to eight decimal hextets. Embedded IPv4 tails are
     converted to two hextets before expanding `::`. */}}
{{- define "ferrum-mesh.ipv6Hextets" -}}
{{- $ip := lower (. | toString) -}}
{{- $valid := and (contains ":" $ip) (regexMatch "^[0-9a-f:.]+$" $ip) (not (regexMatch "[0-9a-f]{5,}" $ip)) -}}
{{- if and $valid (contains "." $ip) -}}
{{- $tail := regexFind "[0-9.]+$" $ip -}}
{{- $tailInt := include "ferrum-mesh.ipv4ToInt" $tail -}}
{{- if not $tailInt -}}
{{- $valid = false -}}
{{- else -}}
{{- $tailValue := $tailInt | int64 -}}
{{- $ip = regexReplaceAll "[0-9.]+$" $ip (printf "%x:%x" (div $tailValue 65536) (mod $tailValue 65536)) -}}
{{- end -}}
{{- end -}}
{{- $hextets := list -}}
{{- if $valid -}}
{{- $sides := splitList "::" $ip -}}
{{- if gt (len $sides) 2 -}}
{{- $valid = false -}}
{{- else if eq (len $sides) 2 -}}
{{- $left := list -}}
{{- $right := list -}}
{{- if index $sides 0 -}}{{- $left = splitList ":" (index $sides 0) -}}{{- end -}}
{{- if index $sides 1 -}}{{- $right = splitList ":" (index $sides 1) -}}{{- end -}}
{{- $missing := sub 8 (add (len $left) (len $right)) | int -}}
{{- if lt $missing 1 -}}
{{- $valid = false -}}
{{- else -}}
{{- range $part := $left -}}{{- $hextets = append $hextets $part -}}{{- end -}}
{{- range until $missing -}}{{- $hextets = append $hextets "0" -}}{{- end -}}
{{- range $part := $right -}}{{- $hextets = append $hextets $part -}}{{- end -}}
{{- end -}}
{{- else -}}
{{- $hextets = splitList ":" $ip -}}
{{- if ne (len $hextets) 8 -}}{{- $valid = false -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $decimal := list -}}
{{- if $valid -}}
{{- range $part := $hextets -}}
{{- if not (regexMatch "^[0-9a-f]{1,4}$" $part) -}}
{{- $valid = false -}}
{{- else -}}
{{- $decimal = append $decimal (include "ferrum-mesh.hexToInt" $part) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $valid (eq (len $decimal) 8) -}}{{- join "," $decimal -}}{{- end -}}
{{- end -}}

{{/* Return the embedded IPv4 integer for an IPv4-mapped IPv6 literal. */}}
{{- define "ferrum-mesh.ipv4MappedToInt" -}}
{{- $hextets := include "ferrum-mesh.ipv6Hextets" (. | toString) -}}
{{- if $hextets -}}
{{- $h := splitList "," $hextets -}}
{{- if and (eq (index $h 0 | int) 0) (eq (index $h 1 | int) 0) (eq (index $h 2 | int) 0) (eq (index $h 3 | int) 0) (eq (index $h 4 | int) 0) (eq (index $h 5 | int) 65535) -}}
{{- add (mul (index $h 6 | int64) 65536) (index $h 7 | int64) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Strictly validate one admin allowlist entry using the same accepted shapes
     as CidrSet::parse_strict: a bare IPv4/IPv6 literal or one literal plus a
     decimal prefix in the family range. IPv4-mapped IPv6 CIDRs require a prefix
     of at least 96 because the runtime canonicalizes them to IPv4. */}}
{{- define "ferrum-mesh.validAdminCidrEntry" -}}
{{- $entry := trim (. | toString) -}}
{{- $parts := splitList "/" $entry -}}
{{- $valid := false -}}
{{- if and $entry (or (eq (len $parts) 1) (eq (len $parts) 2)) -}}
{{- $network := trim (index $parts 0) -}}
{{- $ipValid := false -}}
{{- $isV6 := contains ":" $network -}}
{{- $mappedV6 := false -}}
{{- if $isV6 -}}
{{- $hextets := include "ferrum-mesh.ipv6Hextets" $network -}}
{{- if $hextets -}}
{{- $ipValid = true -}}
{{- $h := splitList "," $hextets -}}
{{- $mappedV6 = and (eq (index $h 0 | int) 0) (eq (index $h 1 | int) 0) (eq (index $h 2 | int) 0) (eq (index $h 3 | int) 0) (eq (index $h 4 | int) 0) (eq (index $h 5 | int) 65535) -}}
{{- end -}}
{{- else -}}
{{- $ipv4 := include "ferrum-mesh.ipv4ToInt" $network -}}
{{- if ne $ipv4 "" -}}{{- $ipValid = true -}}{{- end -}}
{{- end -}}
{{- if $ipValid -}}
{{- if eq (len $parts) 1 -}}
{{- $valid = true -}}
{{- else -}}
{{- $prefixText := trim (index $parts 1) -}}
{{- if regexMatch "^\\+?[0-9]+$" $prefixText -}}
{{- $unsignedPrefix := trimPrefix "+" $prefixText -}}
{{- $normalizedPrefix := regexReplaceAll "^0+" $unsignedPrefix "" -}}
{{- if eq $normalizedPrefix "" -}}{{- $normalizedPrefix = "0" -}}{{- end -}}
{{- if le (len $normalizedPrefix) 3 -}}
{{- $prefix := atoi $normalizedPrefix -}}
{{- if and (not $isV6) (le $prefix 32) -}}{{- $valid = true -}}{{- end -}}
{{- if and $isV6 (le $prefix 128) (or (not $mappedV6) (ge $prefix 96)) -}}{{- $valid = true -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $valid -}}true{{- end -}}
{{- end -}}

{{/* "true" when validated CIDRs jointly cover every address in either family.
     Each CIDR becomes a binary prefix; sibling prefixes collapse recursively to
     their parent, mirroring CidrSet::permits_all_family for /0s and unions. */}}
{{- define "ferrum-mesh.adminAllowlistPermitsAll" -}}
{{- $coverage := dict -}}
{{- range $raw := splitList "," (. | toString) -}}
{{- $parts := splitList "/" (trim $raw) -}}
{{- $network := trim (index $parts 0) -}}
{{- $networkV4 := include "ferrum-mesh.ipv4ToInt" $network -}}
{{- $mappedV4 := include "ferrum-mesh.ipv4MappedToInt" $network -}}
{{- if and (eq $networkV4 "") (ne $mappedV4 "") -}}{{- $networkV4 = $mappedV4 -}}{{- end -}}
{{- if ne $networkV4 "" -}}
{{- $prefix := 32 -}}
{{- if eq (len $parts) 2 -}}
{{- $prefix = atoi (trim (index $parts 1)) -}}
{{- /* Mapped CIDRs are stored as IPv4 after subtracting the 96-bit prefix.
     Bare mapped addresses have no prefix to subtract: they are already a
     single IPv4 host (/32). Subtracting 96 from that default 32 produced a
     negative length and could collapse the family to "permits all". */ -}}
{{- if ne $mappedV4 "" -}}{{- $prefix = sub $prefix 96 | int -}}{{- end -}}
{{- end -}}
{{- $bits := include "ferrum-mesh.ipv4Bits" $networkV4 -}}
{{- $_ := set $coverage (printf "4:%s" (substr 0 $prefix $bits)) true -}}
{{- else -}}
{{- $bits := include "ferrum-mesh.ipv6Bits" $network -}}
{{- if $bits -}}
{{- $prefix := 128 -}}
{{- if eq (len $parts) 2 -}}{{- $prefix = atoi (trim (index $parts 1)) -}}{{- end -}}
{{- $_ := set $coverage (printf "6:%s" (substr 0 $prefix $bits)) true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{/* Collapse from leaves toward each family root. Re-reading keys at every
     depth lets a parent created at depth N participate at depth N-1. */}}
{{- range $depth := untilStep 128 0 -1 -}}
{{- range $key := keys $coverage -}}
{{- $keyParts := splitList ":" $key -}}
{{- $family := index $keyParts 0 -}}
{{- $bits := index $keyParts 1 -}}
{{- if eq (len $bits) $depth -}}
{{- $parentBits := substr 0 (sub $depth 1 | int) $bits -}}
{{- $lastBit := substr (sub $depth 1 | int) $depth $bits -}}
{{- $siblingBit := ternary "0" "1" (eq $lastBit "1") -}}
{{- $sibling := printf "%s:%s%s" $family $parentBits $siblingBit -}}
{{- if hasKey $coverage $sibling -}}
{{- $_ := set $coverage (printf "%s:%s" $family $parentBits) true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if or (hasKey $coverage "4:") (hasKey $coverage "6:") -}}true{{- end -}}
{{- end -}}

{{/* Return "true" when one comma-separated allowlist entry contains the supplied
     probe source. This mirrors IpNet::contains for both IP families so ordinary
     covering subnets (127.0.0.0/8, 10.0.0.0/8, fd00::/8, ...) are accepted. */}}
{{- define "ferrum-mesh.adminAllowlistContainsIp" -}}
{{- $target := .ip | toString | trimPrefix "[" | trimSuffix "]" | lower -}}
{{- $targetV4 := include "ferrum-mesh.ipv4ToInt" $target -}}
{{- if eq $targetV4 "" -}}{{- $targetV4 = include "ferrum-mesh.ipv4MappedToInt" $target -}}{{- end -}}
{{- $targetV6 := include "ferrum-mesh.ipv6Hextets" $target -}}
{{- $found := false -}}
{{- range $raw := splitList "," (.allowedCidrs | default "") -}}
{{- $entry := trim $raw | lower -}}
{{- $parts := splitList "/" $entry -}}
{{- $network := trim (index $parts 0) -}}
{{- $networkV4 := include "ferrum-mesh.ipv4ToInt" $network -}}
{{- $networkMappedV4 := include "ferrum-mesh.ipv4MappedToInt" $network -}}
{{- if and (eq $networkV4 "") $networkMappedV4 -}}{{- $networkV4 = $networkMappedV4 -}}{{- end -}}
{{- $networkV6 := include "ferrum-mesh.ipv6Hextets" $network -}}
{{- if eq (len $parts) 1 -}}
{{- if and (ne $targetV4 "") (ne $networkV4 "") (eq ($targetV4 | int64) ($networkV4 | int64)) -}}
{{- $found = true -}}
{{- else if and $targetV6 $networkV6 (eq $targetV6 $networkV6) -}}
{{- $found = true -}}
{{- end -}}
{{- else if and (eq (len $parts) 2) (regexMatch "^\\+?[0-9]+$" (trim (index $parts 1))) -}}
{{- $prefix := atoi (trim (index $parts 1)) -}}
{{- $v4Prefix := $prefix -}}
{{- if $networkMappedV4 -}}{{- $v4Prefix = sub $prefix 96 | int -}}{{- end -}}
{{- if and (ne $targetV4 "") (ne $networkV4 "") (ge $v4Prefix 0) (le $v4Prefix 32) -}}
{{- $blockSize := 1 | int64 -}}
{{- range until (sub 32 $v4Prefix | int) -}}{{- $blockSize = mul $blockSize 2 -}}{{- end -}}
{{- if eq (div ($targetV4 | int64) $blockSize) (div ($networkV4 | int64) $blockSize) -}}{{- $found = true -}}{{- end -}}
{{- end -}}
{{/* A mapped IPv6 query still matches ordinary IPv6 rules at runtime. Mapped
     networks are excluded here because the runtime folds those into IPv4. */}}
{{- if and (not $networkMappedV4) $targetV6 $networkV6 (ge $prefix 0) (le $prefix 128) -}}
{{- $targetParts := splitList "," $targetV6 -}}
{{- $networkParts := splitList "," $networkV6 -}}
{{- $matches := true -}}
{{- $fullHextets := div $prefix 16 | int -}}
{{- range $i := until $fullHextets -}}
{{- if ne (index $targetParts $i | int) (index $networkParts $i | int) -}}{{- $matches = false -}}{{- end -}}
{{- end -}}
{{- $remainingBits := mod $prefix 16 | int -}}
{{- if and $matches (gt $remainingBits 0) -}}
{{- $blockSize := 1 -}}
{{- range until (sub 16 $remainingBits | int) -}}{{- $blockSize = mul $blockSize 2 -}}{{- end -}}
{{- if ne (div (index $targetParts $fullHextets | int) $blockSize) (div (index $networkParts $fullHextets | int) $blockSize) -}}{{- $matches = false -}}{{- end -}}
{{- end -}}
{{- if $matches -}}{{- $found = true -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $found -}}true{{- end -}}
{{- end -}}

{{/*
Enabled injector must have exactly one webhook trust source: a base64 PEM
caBundle, or cert-manager.io/inject-ca-from. Empty caBundle plus failurePolicy
Fail would render a webhook Kubernetes cannot authenticate. Never weaken
failurePolicy to Ignore to make that configuration render.
*/}}
{{- define "ferrum-mesh.validateInjectorTrust" -}}
{{- if .Values.injector.enabled -}}
{{- $ca := .Values.injector.caBundle | toString | trim -}}
{{- $cm := .Values.injector.certManager | default dict -}}
{{- $injectFrom := index $cm "injectCaFrom" | default "" | toString | trim -}}
{{- $hasCa := ne $ca "" -}}
{{- $hasInject := ne $injectFrom "" -}}
{{- if and $hasCa $hasInject -}}
{{- fail "injector requires exactly one trust source: set injector.caBundle or injector.certManager.injectCaFrom, not both" -}}
{{- end -}}
{{- if not (or $hasCa $hasInject) -}}
{{- fail "injector.enabled=true requires injector.caBundle (base64-encoded PEM CA) or injector.certManager.injectCaFrom (cert-manager.io/inject-ca-from namespace/certificate). An empty caBundle with failurePolicy Fail renders a webhook Kubernetes cannot authenticate. Do not set failurePolicy to Ignore to bypass this." -}}
{{- end -}}
{{- if $hasCa -}}
{{- if not (regexMatch "^[A-Za-z0-9+/]+={0,2}$" $ca) -}}
{{- fail "injector.caBundle must be SINGLE-LINE base64 of a PEM CA certificate (decoded value must contain BEGIN CERTIFICATE). Wrapped base64 is rejected because the rendered webhook would be invalid: produce it with `base64 -w0 < ca.crt` (macOS: `base64 < ca.crt | tr -d '\n'`)." -}}
{{- end -}}
{{- $decoded := $ca | b64dec -}}
{{- if not (contains "BEGIN CERTIFICATE" $decoded) -}}
{{- fail "injector.caBundle must be SINGLE-LINE base64 of a PEM CA certificate (decoded value must contain BEGIN CERTIFICATE). Wrapped base64 is rejected because the rendered webhook would be invalid: produce it with `base64 -w0 < ca.crt` (macOS: `base64 < ca.crt | tr -d '\n'`)." -}}
{{- end -}}
{{- end -}}
{{- if $hasInject -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $injectFrom) -}}
{{- fail "injector.certManager.injectCaFrom must be namespace/certificate-name (DNS-1123 labels)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Ferrum-owned CRDs live in templates/ so helm upgrade applies schema changes.
Helm's crds/ directory is install-once and would leave clusters on a stale
UDPResponseAmplificationPolicy schema. Skipping install requires an explicit
acknowledgement. An unmanaged CRD from the former crds/ directory must be
adopted (crds.adoptExisting=true plus helm upgrade --take-ownership).
*/}}
{{- define "ferrum-mesh.validateCrds" -}}
{{- $crds := .Values.crds | default dict -}}
{{- $install := true -}}
{{- if hasKey $crds "install" -}}
{{- $install = $crds.install -}}
{{- end -}}
{{- $skipAck := false -}}
{{- if hasKey $crds "skipInstallAcknowledged" -}}
{{- $skipAck = $crds.skipInstallAcknowledged -}}
{{- end -}}
{{- if and (not $install) (not $skipAck) -}}
{{- fail "crds.install=false leaves UDPResponseAmplificationPolicy unmanaged across helm upgrade. Set crds.install=true (default) so helm upgrade applies the CRD, or set crds.skipInstallAcknowledged=true after applying the chart CRD with kubectl apply --server-side. See docs/upgrade_guide.md." -}}
{{- end -}}
{{- if and $install $skipAck -}}
{{- fail "crds.skipInstallAcknowledged=true is only valid when crds.install=false" -}}
{{- end -}}
{{- end -}}
