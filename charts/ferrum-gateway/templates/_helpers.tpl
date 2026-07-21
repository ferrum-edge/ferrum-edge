{{/*
Ferrum Edge core-gateway chart helpers.

Design notes:
- Templates intentionally fail at render time for invalid or unsafe settings so
  an un-bootable pod (missing DB URL / JWT secret, or a non-loopback plaintext
  admin bind the binary hard-fails on in database/cp modes) is never rendered.
- Secret material is never rendered into ConfigMaps and never inlined into logs;
  credentials flow only through env values or Secret references the operator owns.
*/}}

{{- define "ferrum-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Render a non-negative int64 as a fixed-width binary string. Widths used by
     this chart are 16 (one IPv6 hextet) and 32 (one IPv4 address). */}}
{{- define "ferrum-gateway.unsignedBinaryBits" -}}
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

{{- define "ferrum-gateway.ipv4Bits" -}}
{{- include "ferrum-gateway.unsignedBinaryBits" (dict "value" (. | int64) "width" 32) -}}
{{- end -}}

{{- define "ferrum-gateway.ipv6Bits" -}}
{{- $hextets := include "ferrum-gateway.ipv6Hextets" (. | toString) -}}
{{- $bits := "" -}}
{{- if $hextets -}}
{{- range $part := splitList "," $hextets -}}
{{- $bits = printf "%s%s" $bits (include "ferrum-gateway.unsignedBinaryBits" (dict "value" ($part | int64) "width" 16)) -}}
{{- end -}}
{{- end -}}
{{- $bits -}}
{{- end -}}

{{/*
Suffixed names must leave room for the suffix BEFORE truncation, otherwise a
fullname already at the 63-char DNS-label limit drops the suffix and two
Services collide. Truncate the base to (63 - len(suffix)) first, then append.
*/}}
{{- define "ferrum-gateway.suffixedName" -}}
{{- $suffix := .suffix -}}
{{- $base := .base | trunc (int (sub 63 (len $suffix))) | trimSuffix "-" -}}
{{- printf "%s%s" $base $suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.cpGrpcServiceName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-grpc") -}}
{{- end -}}

{{- define "ferrum-gateway.adminServiceName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-admin") -}}
{{- end -}}

{{- define "ferrum-gateway.configMapName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-config") -}}
{{- end -}}

{{- define "ferrum-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferrum-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ferrum-gateway.labels" -}}
helm.sh/chart: {{ include "ferrum-gateway.chart" . }}
{{ include "ferrum-gateway.selectorLabels" . }}
app.kubernetes.io/part-of: ferrum-edge
app.kubernetes.io/component: gateway
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ferrum-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-gateway.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* File-mode config path (kept in sync with the ConfigMap mount). */}}
{{- define "ferrum-gateway.fileConfigPath" -}}
{{- $file := .Values.file | default dict -}}
{{- $dir := $file.mountPath | default "/etc/ferrum/config" -}}
{{- printf "%s/%s" (trimSuffix "/" $dir) ($file.fileName | default "config.yaml") -}}
{{- end -}}

{{/* Admin plaintext HTTP port (0 disables plaintext admin). */}}
{{- define "ferrum-gateway.adminHttpPort" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "adminHttp" -}}{{- $ports.adminHttp -}}{{- else -}}9000{{- end -}}
{{- end -}}

{{/* Admin HTTPS port (0 disables admin HTTPS). */}}
{{- define "ferrum-gateway.adminHttpsPort" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "adminHttps" -}}{{- $ports.adminHttps -}}{{- else -}}9443{{- end -}}
{{- end -}}

{{/* "true" when HTTP/3 (QUIC) is enabled through the supported env passthrough.
     FERRUM_ENABLE_HTTP3 is not a chart first-class value, so operators set it via
     env/extraEnv; when true (parsed like the binary's bool: trimmed, lowercased,
     "true"/"1") the serving modes start a QUIC listener on FERRUM_PROXY_HTTPS_PORT
     (docs/http3.md, src/modes/{database,file,data_plane}.rs). The proxy Service
     must then publish that HTTPS port on UDP or kube-proxy won't forward QUIC.
     valueFrom-sourced extraEnv values can't be inspected here — those installs
     must hand-add the UDP Service port (documented in values.yaml/README). */}}
{{- define "ferrum-gateway.http3Enabled" -}}
{{- $enabled := false -}}
{{- $env := .Values.env | default dict -}}
{{- if hasKey $env "FERRUM_ENABLE_HTTP3" -}}
{{- if has (lower (trim (toString (get $env "FERRUM_ENABLE_HTTP3")))) (list "true" "1") -}}{{- $enabled = true -}}{{- end -}}
{{- end -}}
{{- range $entry := .Values.extraEnv | default list -}}
{{- if and (eq (toString $entry.name) "FERRUM_ENABLE_HTTP3") (has (lower (trim (toString ($entry.value | default "")))) (list "true" "1")) -}}{{- $enabled = true -}}{{- end -}}
{{- end -}}
{{- if $enabled -}}true{{- end -}}
{{- end -}}

{{/* "true" when a TLS *_SOURCE variable is supplied through env/extraEnv or
     through one of Ferrum's external-secret resolver suffixes. A matching
     secretFileMounts base emits <name>_FILE and resolves into the same source
     variable before EnvConfig is parsed, so it counts too. Literal empty values
     do not configure a source; valueFrom entries are conservatively treated as
     configured because their runtime value is intentionally opaque to Helm. */}}
{{- define "ferrum-gateway.tlsSourceConfigured" -}}
{{- $root := .root -}}
{{- $base := .name -}}
{{- $configured := false -}}
{{- $candidates := list $base -}}
{{- range $suffix := list "_VAULT" "_AWS" "_AZURE" "_GCP" "_FILE" -}}
{{- $candidates = append $candidates (printf "%s%s" $base $suffix) -}}
{{- end -}}
{{- $env := $root.Values.env | default dict -}}
{{- range $name := $candidates -}}
{{- if and (hasKey $env $name) (ne (trim (toString (get $env $name))) "") -}}
{{- $configured = true -}}
{{- end -}}
{{- end -}}
{{- range $entry := $root.Values.extraEnv | default list -}}
{{- $name := toString ($entry.name | default "") -}}
{{- $hasValue := and (hasKey $entry "value") (ne (trim (toString (get $entry "value"))) "") -}}
{{- $hasValueFrom := and (hasKey $entry "valueFrom") (not (empty (get $entry "valueFrom"))) -}}
{{- if and (has $name $candidates) (or $hasValue $hasValueFrom) -}}
{{- $configured = true -}}
{{- end -}}
{{- end -}}
{{- range $mount := $root.Values.secretFileMounts | default list -}}
{{- if eq (toString ($mount.name | default "")) $base -}}
{{- $configured = true -}}
{{- end -}}
{{- end -}}
{{- if $configured -}}true{{- end -}}
{{- end -}}

{{/* "true" when a server TLS surface has a complete cert/key pair from either
     its first-class Secret mount or the matching supported *_SOURCE envs. */}}
{{- define "ferrum-gateway.serverTlsConfigured" -}}
{{- $surface := .surface | default dict -}}
{{- $pathPair := and $surface.enabled $surface.secretName -}}
{{- $certSource := include "ferrum-gateway.tlsSourceConfigured" (dict "root" .root "name" .certSource) -}}
{{- $keySource := include "ferrum-gateway.tlsSourceConfigured" (dict "root" .root "name" .keySource) -}}
{{- if or $pathPair (and $certSource $keySource) -}}true{{- end -}}
{{- end -}}

{{/* Host the computed exec probes must dial. The admin listener binds ONLY the
     configured FERRUM_ADMIN_BIND_ADDRESS, so a probe dialing 127.0.0.1 cannot
     reach a listener bound to a concrete non-loopback address (a pod/host IP, or
     even 127.0.0.2) — the kubelet then restart-loops the pod. Target the exact
     configured bind whenever it is concrete, and fall back to loopback ONLY for
     the wildcard forms:
       - IPv4 wildcard 0.0.0.0 (and the empty default, which binds loopback) → 127.0.0.1
       - IPv6 wildcard :: / [::] → ::1 (a [::]-bound listener is not guaranteed to
         accept v4-mapped 127.0.0.1: acceptance depends on IPV6_V6ONLY / dual-stack,
         which the runtime does not force; ::1 always reaches :: or ::1)
       - any concrete literal (127.0.0.1, 127.0.0.2, 10.0.0.5, ::1, fd00::1, ...) →
         itself; `ferrum-edge health --host` brackets bare IPv6 literals for us. */}}
{{- define "ferrum-gateway.probeHost" -}}
{{- $bind := (.Values.admin | default dict).bindAddress | default "" -}}
{{- $bind = trimSuffix "]" (trimPrefix "[" $bind) -}}
{{- if or (eq $bind "") (eq $bind "0.0.0.0") -}}127.0.0.1
{{- else if eq $bind "::" -}}::1
{{- else -}}{{ $bind }}
{{- end -}}
{{- end -}}

{{/* Source address the admin listener observes for the computed exec probe.
     Linux selects 127.0.0.1 when connecting to any concrete 127/8 destination;
     other concrete/wildcard probe hosts use the same local address they dial. */}}
{{- define "ferrum-gateway.probeSource" -}}
{{- $host := include "ferrum-gateway.probeHost" . -}}
{{- if regexMatch "^127\\." $host -}}127.0.0.1
{{- else -}}{{ $host }}
{{- end -}}
{{- end -}}

{{/* "true" when the value parses as a strict IPv4 or IPv6 literal, else "".
     Mirrors the runtime's IpAddr parsing: IPv4 octets are canonical decimal and
     IPv6 is fully expanded/validated, including an optional embedded IPv4 tail. */}}
{{- define "ferrum-gateway.isIpLiteral" -}}
{{- $v := . | toString -}}
{{- $octet := "(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := printf "^%s\\.%s\\.%s\\.%s$" $octet $octet $octet $octet -}}
{{- if regexMatch $ipv4 $v -}}true
{{- else if and (contains ":" $v) (include "ferrum-gateway.ipv6Hextets" $v) -}}true
{{- end -}}
{{- end -}}

{{/* Convert a validated IPv4 literal to its unsigned 32-bit integer value. */}}
{{- define "ferrum-gateway.ipv4ToInt" -}}
{{- $v := . | toString -}}
{{- if and (include "ferrum-gateway.isIpLiteral" $v) (not (contains ":" $v)) -}}
{{- $parts := splitList "." $v -}}
{{- add (mul (index $parts 0 | int64) 16777216) (mul (index $parts 1 | int64) 65536) (mul (index $parts 2 | int64) 256) (index $parts 3 | int64) -}}
{{- end -}}
{{- end -}}

{{/* Convert one validated IPv6 hextet to an integer. Helm has no base-16 atoi. */}}
{{- define "ferrum-gateway.hexToInt" -}}
{{- $digits := dict "0" 0 "1" 1 "2" 2 "3" 3 "4" 4 "5" 5 "6" 6 "7" 7 "8" 8 "9" 9 "a" 10 "b" 11 "c" 12 "d" 13 "e" 14 "f" 15 -}}
{{- $value := 0 -}}
{{- range $digit := regexFindAll "." (lower (. | toString)) -1 -}}
{{- $value = add (mul $value 16) (get $digits $digit) -}}
{{- end -}}
{{- $value -}}
{{- end -}}

{{/* Expand an IPv6 literal to eight decimal hextets. Embedded IPv4 tails are
     converted to two hextets before expanding `::`. */}}
{{- define "ferrum-gateway.ipv6Hextets" -}}
{{- $ip := lower (. | toString) -}}
{{- $valid := and (contains ":" $ip) (regexMatch "^[0-9a-f:.]+$" $ip) (not (regexMatch "[0-9a-f]{5,}" $ip)) -}}
{{- if and $valid (contains "." $ip) -}}
{{- $tail := regexFind "[0-9.]+$" $ip -}}
{{- $tailInt := include "ferrum-gateway.ipv4ToInt" $tail -}}
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
{{- $decimal = append $decimal (include "ferrum-gateway.hexToInt" $part) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $valid (eq (len $decimal) 8) -}}{{- join "," $decimal -}}{{- end -}}
{{- end -}}

{{/* Return the embedded IPv4 integer for an IPv4-mapped IPv6 literal. */}}
{{- define "ferrum-gateway.ipv4MappedToInt" -}}
{{- $hextets := include "ferrum-gateway.ipv6Hextets" (. | toString) -}}
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
{{- define "ferrum-gateway.validAdminCidrEntry" -}}
{{- $entry := trim (. | toString) -}}
{{- $parts := splitList "/" $entry -}}
{{- $valid := false -}}
{{- if and $entry (or (eq (len $parts) 1) (eq (len $parts) 2)) -}}
{{- $network := trim (index $parts 0) -}}
{{- $ipValid := false -}}
{{- $isV6 := contains ":" $network -}}
{{- $mappedV6 := false -}}
{{- if $isV6 -}}
{{- $hextets := include "ferrum-gateway.ipv6Hextets" $network -}}
{{- if $hextets -}}
{{- $ipValid = true -}}
{{- $h := splitList "," $hextets -}}
{{- $mappedV6 = and (eq (index $h 0 | int) 0) (eq (index $h 1 | int) 0) (eq (index $h 2 | int) 0) (eq (index $h 3 | int) 0) (eq (index $h 4 | int) 0) (eq (index $h 5 | int) 65535) -}}
{{- end -}}
{{- else -}}
{{- $ipv4 := include "ferrum-gateway.ipv4ToInt" $network -}}
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
{{- define "ferrum-gateway.adminAllowlistPermitsAll" -}}
{{- $coverage := dict -}}
{{- range $raw := splitList "," (. | toString) -}}
{{- $parts := splitList "/" (trim $raw) -}}
{{- $network := trim (index $parts 0) -}}
{{- $networkV4 := include "ferrum-gateway.ipv4ToInt" $network -}}
{{- $mappedV4 := include "ferrum-gateway.ipv4MappedToInt" $network -}}
{{- if and (eq $networkV4 "") (ne $mappedV4 "") -}}{{- $networkV4 = $mappedV4 -}}{{- end -}}
{{- if ne $networkV4 "" -}}
{{- $prefix := 32 -}}
{{- if eq (len $parts) 2 -}}{{- $prefix = atoi (trim (index $parts 1)) -}}{{- end -}}
{{- if ne $mappedV4 "" -}}{{- $prefix = sub $prefix 96 | int -}}{{- end -}}
{{- $bits := include "ferrum-gateway.ipv4Bits" $networkV4 -}}
{{- $_ := set $coverage (printf "4:%s" (substr 0 $prefix $bits)) true -}}
{{- else -}}
{{- $bits := include "ferrum-gateway.ipv6Bits" $network -}}
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
{{- define "ferrum-gateway.adminAllowlistContainsIp" -}}
{{- $target := .ip | toString | trimPrefix "[" | trimSuffix "]" | lower -}}
{{- $targetV4 := include "ferrum-gateway.ipv4ToInt" $target -}}
{{- if eq $targetV4 "" -}}{{- $targetV4 = include "ferrum-gateway.ipv4MappedToInt" $target -}}{{- end -}}
{{- $targetV6 := include "ferrum-gateway.ipv6Hextets" $target -}}
{{- $found := false -}}
{{- range $raw := splitList "," (.allowedCidrs | default "") -}}
{{- $entry := trim $raw | lower -}}
{{- $parts := splitList "/" $entry -}}
{{- $network := trim (index $parts 0) -}}
{{- $networkV4 := include "ferrum-gateway.ipv4ToInt" $network -}}
{{- $networkMappedV4 := include "ferrum-gateway.ipv4MappedToInt" $network -}}
{{- if and (eq $networkV4 "") $networkMappedV4 -}}{{- $networkV4 = $networkMappedV4 -}}{{- end -}}
{{- $networkV6 := include "ferrum-gateway.ipv6Hextets" $network -}}
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
Return the first DP CP URL that is PLAINTEXT to a non-loopback host, or "" if
none. Mirrors cp_dp_grpc_url_is_nonloopback_plaintext() in
src/config/env_config.rs: http:// or grpc:// scheme to a host that is not
127.0.0.0/8, ::1, or (a subdomain of) localhost. The binary remains
authoritative for hosts this best-effort regex does not classify.
*/}}
{{- define "ferrum-gateway.dpPlaintextUrl" -}}
{{- $bad := "" -}}
{{- range $u := splitList "," (.Values.dp.cpGrpcUrls | default "") -}}
{{- $url := trim $u -}}
{{- if and $url (regexMatch "(?i)^(http|grpc)://" $url) -}}
{{- if not (regexMatch "(?i)^(http|grpc)://(127\\.[0-9]+\\.[0-9]+\\.[0-9]+|localhost|[^/@:]*\\.localhost|\\[::1\\])(:[0-9]+)?(/|$)" $url) -}}
{{- if not $bad -}}{{- $bad = $url -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $bad -}}
{{- end -}}

{{/* First DP CP URL whose scheme is not one the binary accepts, or "". The DP
     runtime parses every FERRUM_DP_CP_GRPC_URLS entry and rejects any scheme
     other than http/https/grpc/grpcs at startup, so surface typos (htt://,
     schemeless host:port) and uppercase variants at render time. */}}
{{- define "ferrum-gateway.dpInvalidSchemeUrl" -}}
{{- $bad := "" -}}
{{- range $u := splitList "," (.Values.dp.cpGrpcUrls | default "") -}}
{{- $url := trim $u -}}
{{- if $url -}}
{{- $scheme := lower (regexFind "^[a-zA-Z0-9+.-]*" $url) -}}
{{- if not (has $scheme (list "http" "https" "grpc" "grpcs")) -}}
{{- if not $bad -}}{{- $bad = $url -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $bad -}}
{{- end -}}

{{/* First DP CP URL that carries a scheme but no host (e.g. "https://",
     "grpc://:50051"), or "". The DP runtime parses every FERRUM_DP_CP_GRPC_URLS
     entry with url::Url and rejects a URL whose host is empty, so a scheme-only
     value renders cleanly yet fails at boot. Strip the scheme and any userinfo,
     then require a non-empty host before the port/path/query/fragment. */}}
{{- define "ferrum-gateway.dpHostlessUrl" -}}
{{- $bad := "" -}}
{{- range $u := splitList "," (.Values.dp.cpGrpcUrls | default "") -}}
{{- $url := trim $u -}}
{{- if and $url (regexMatch "(?i)^[a-z0-9+.-]+://" $url) -}}
{{- $rest := regexReplaceAll "(?i)^[a-z0-9+.-]+://" $url "" -}}
{{- $rest = regexReplaceAll "^[^/?#@]*@" $rest "" -}}
{{- $host := regexFind "^[^:/?#]*" $rest -}}
{{- if not $host -}}
{{- if not $bad -}}{{- $bad = $url -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $bad -}}
{{- end -}}

{{/* True when a secret source (value / existingSecret.name / valueFrom) is set. */}}
{{- define "ferrum-gateway.sourceConfigured" -}}
{{- $source := . | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- if or $source.value $source.valueFrom $existing.name -}}true{{- end -}}
{{- end -}}

{{/* Count secretFileMounts entries that resolve one required base env var. */}}
{{- define "ferrum-gateway.secretFileSourceCount" -}}
{{- $count := 0 -}}
{{- range .root.Values.secretFileMounts -}}
{{- if eq (.name | default "") $.envName -}}
{{- $count = add $count 1 -}}
{{- end -}}
{{- end -}}
{{- $count -}}
{{- end -}}

{{/*
Validate a secret source: at most one of value, existingSecret.name, valueFrom,
or the matching secretFileMounts/_FILE source, and (optionally) a minimum
inline-value length. When .optional is truthy the credential may be omitted
entirely (count 0 is allowed) but supplying more than one source is still a
render-time conflict — the binary rejects multiple sources for one base key even
where the credential itself is optional (e.g. the file-mode admin JWT). When
.optional is falsy exactly one source is required.
*/}}
{{- define "ferrum-gateway.validateOneSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- $fileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" .root "envName" .envName) | int -}}
{{- $count = add $count $fileCount -}}
{{- if .optional -}}
{{- if gt $count 1 -}}
{{- fail (printf "%s accepts at most one source, but %d are configured; the binary rejects multiple sources for one base key. Set only one of value, existingSecret.name, valueFrom, or a secretFileMounts entry name=%s (it is optional in this mode)." $label $count .envName) -}}
{{- end -}}
{{- else -}}
{{- if ne $count 1 -}}
{{- fail (printf "%s requires exactly one of value, existingSecret.name, valueFrom, or secretFileMounts entry name=%s" $label .envName) -}}
{{- end -}}
{{- end -}}
{{- if and $source.value .minLength (lt (len $source.value) (.minLength | int)) -}}
{{- fail (printf "%s.value must be at least %d characters" $label (.minLength | int)) -}}
{{- end -}}
{{- end -}}

{{/* Render an env var from a secret source (value or Secret reference). */}}
{{- define "ferrum-gateway.renderSecretEnv" -}}
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

{{- define "ferrum-gateway.uriComponentEncode" -}}
{{- . | toString | urlquery | replace "+" "%20" -}}
{{- end -}}

{{- define "ferrum-gateway.structuredDbUrl" -}}
{{- $db := . -}}
{{- $port := "" -}}
{{- if $db.port -}}{{- $port = printf ":%v" $db.port -}}{{- end -}}
{{- $host := $db.host -}}
{{- if and (contains ":" $host) (not (hasPrefix "[" $host)) -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- $auth := "" -}}
{{- if and $db.username $db.password -}}
{{- $auth = printf "%s:%s@" (include "ferrum-gateway.uriComponentEncode" $db.username) (include "ferrum-gateway.uriComponentEncode" $db.password) -}}
{{- end -}}
{{- $path := "" -}}
{{- if $db.name -}}{{- $path = printf "/%s" (include "ferrum-gateway.uriComponentEncode" $db.name) -}}{{- end -}}
{{- $query := "" -}}
{{- if $db.params -}}
{{- $pairs := list -}}
{{- range $key := keys $db.params | sortAlpha -}}
{{- $pairs = append $pairs (printf "%s=%s" (include "ferrum-gateway.uriComponentEncode" $key) (include "ferrum-gateway.uriComponentEncode" (get $db.params $key))) -}}
{{- end -}}
{{- if $pairs -}}{{- $query = printf "?%s" (join "&" $pairs) -}}{{- end -}}
{{- end -}}
{{- printf "%s://%s%s%s%s%s" $db.type $auth $host $port $path $query -}}
{{- end -}}

{{- define "ferrum-gateway.renderDbUrlEnv" -}}
{{- $db := .Values.database | default dict -}}
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
  value: {{ include "ferrum-gateway.structuredDbUrl" $db | quote }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Validation: fail render on missing/unsafe configuration.
--------------------------------------------------------------------------- */}}
{{- define "ferrum-gateway.validateDatabase" -}}
{{- $db := .Values.database | default dict -}}
{{- if not $db.type -}}
{{- fail (printf "database.type is required for mode=%s (one of: sqlite, postgres, mysql, mongodb)" .Values.mode) -}}
{{- end -}}
{{- if not (has $db.type (list "sqlite" "postgres" "mysql" "mongodb")) -}}
{{- fail "database.type must be one of: sqlite, postgres, mysql, mongodb" -}}
{{- end -}}
{{- $urlCount := 0 -}}
{{- $existing := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
{{- $dbUrlFileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" . "envName" "FERRUM_DB_URL") | int -}}
{{- if $db.url -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $db.urlFrom -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if and (eq $db.type "sqlite") $sqlite.path -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $db.host -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- $urlCount = add $urlCount $dbUrlFileCount -}}
{{- if ne $urlCount 1 -}}
{{- fail "database requires exactly one URL source: url, urlFrom, existingSecret.name, sqlite.path, structured host settings, or secretFileMounts entry name=FERRUM_DB_URL" -}}
{{- end -}}
{{- if and (ne $db.type "sqlite") $sqlite.path -}}
{{- fail "database.sqlite.path is valid only when database.type=sqlite" -}}
{{- end -}}
{{- if and (eq $db.type "sqlite") $db.host -}}
{{- fail "database.host is not valid when database.type=sqlite" -}}
{{- end -}}
{{- if and $db.host (or (eq $db.type "postgres") (eq $db.type "mysql")) (not $db.name) -}}
{{- fail "database.name is required for structured postgres/mysql database URLs" -}}
{{- end -}}
{{- if or $db.username $db.password -}}
{{- if not $db.host -}}{{- fail "database username/password require structured host settings" -}}{{- end -}}
{{- if not (and $db.username $db.password) -}}{{- fail "database structured credentials require both username and password, or neither" -}}{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-gateway.validate" -}}
{{- $mode := .Values.mode | default "" -}}
{{- if eq $mode "migrate" -}}
{{- fail "mode=migrate is not deployed by the ferrum-gateway or ferrum-mesh charts. Run explicit migrate as an external pre-deploy Kubernetes Job (see charts/ferrum-gateway/examples/migrate-job-*.yaml and docs/kubernetes_deployment.md#explicit-migrate-mode-external-job). database/cp installs still auto-apply pending core schema migrations on startup." -}}
{{- else if not (has $mode (list "database" "file" "cp" "dp")) -}}
{{- fail (printf "mode must be one of: database, file, cp, dp (got %q). The mesh, injector, and node_agent modes live in the ferrum-mesh chart, not this one. Explicit migrate mode is an external Job workflow, not a chart mode." $mode) -}}
{{- end -}}
{{/* A generic secretFileMount emits <name>_FILE. Most chart-managed variables
     are also rendered directly, which gives the external-secret resolver two
     providers for the same base and aborts startup. Only the three first-class
     DB/JWT source guards suppress their direct env when a matching file source
     is selected. */}}
{{- $managedFileSources := list "FERRUM_DB_URL" "FERRUM_ADMIN_JWT_SECRET" "FERRUM_CP_DP_GRPC_JWT_SECRET" -}}
{{- $reservedEnv := splitList " " (include "ferrum-gateway.reservedEnv" .) -}}
{{- range $mount := .Values.secretFileMounts | default list -}}
{{- $name := $mount.name | default "" -}}
{{- if and (has $name $reservedEnv) (not (has $name $managedFileSources)) -}}
{{- fail (printf "secretFileMounts entry name=%s conflicts with a chart-managed env that is rendered directly; only FERRUM_DB_URL, FERRUM_ADMIN_JWT_SECRET, and FERRUM_CP_DP_GRPC_JWT_SECRET support replacing their first-class source with a matching _FILE mount" $name) -}}
{{- end -}}
{{- end -}}
{{- if or (eq $mode "database") (eq $mode "cp") -}}
{{- include "ferrum-gateway.validateDatabase" . -}}
{{- end -}}
{{- if or (eq $mode "database") (eq $mode "cp") (eq $mode "dp") -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "admin.jwtSecret" "source" (.Values.admin.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_ADMIN_JWT_SECRET") -}}
{{- else if eq $mode "file" -}}
{{/* file mode generates a random read-only admin JWT when none is supplied, so
     the credential is optional — but if BOTH admin.jwtSecret.* and a
     secretFileMounts entry for FERRUM_ADMIN_JWT_SECRET are configured the chart
     would render both FERRUM_ADMIN_JWT_SECRET and _FILE, and startup rejects
     multiple sources for one base key. Enforce the same at-most-one conflict. */}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "admin.jwtSecret" "source" (.Values.admin.jwtSecret | default dict) "minLength" 32 "optional" true "root" . "envName" "FERRUM_ADMIN_JWT_SECRET") -}}
{{- end -}}
{{- $grpc := .Values.grpc | default dict -}}
{{- $tlsAll := .Values.tls | default dict -}}
{{- if eq $mode "cp" -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "grpc.jwtSecret" "source" ($grpc.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_CP_DP_GRPC_JWT_SECRET") -}}
{{/* The binary rejects a non-loopback PLAINTEXT CP gRPC bind (no TLS) unless
     FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true (src/config/env_config.rs). */}}
{{- $cpBind := .Values.cp.grpcBindAddress | default "0.0.0.0" -}}
{{/* The runtime parses FERRUM_CP_GRPC_LISTEN_ADDR with SocketAddr::parse
     (cp_grpc_socket_addr, src/config/env_config.rs), which requires an IP
     literal host and rejects hostnames like "localhost" — so a hostname bind
     renders cleanly and then exits at boot. Reject any non-IP host at render.
     Brackets on an IPv6 literal are stripped first (the listen-addr helper
     re-adds them). */}}
{{- $cpHasOpenBracket := hasPrefix "[" $cpBind -}}
{{- $cpHasCloseBracket := hasSuffix "]" $cpBind -}}
{{- if ne $cpHasOpenBracket $cpHasCloseBracket -}}
{{- fail (printf "cp.grpcBindAddress=%q has mismatched IPv6 brackets; use a bare IPv6 literal such as :: or a balanced bracketed literal such as [::]" $cpBind) -}}
{{- end -}}
{{- $cpBindHost := $cpBind | trimPrefix "[" | trimSuffix "]" -}}
{{- if and $cpHasOpenBracket (not (contains ":" $cpBindHost)) -}}
{{- fail (printf "cp.grpcBindAddress=%q brackets a non-IPv6 address; IPv4 bind addresses must use bare form such as 127.0.0.1 or 0.0.0.0" $cpBind) -}}
{{- end -}}
{{- if not (include "ferrum-gateway.isIpLiteral" $cpBindHost) -}}
{{- fail (printf "cp.grpcBindAddress=%q is not an IP literal: the runtime parses FERRUM_CP_GRPC_LISTEN_ADDR as an IP:port socket address and rejects hostnames (localhost, ferrum-cp, ...) at boot. Use an IP literal — 0.0.0.0 or :: to expose the CP gRPC listener, or 127.0.0.1/::1 for a loopback bind." $cpBind) -}}
{{- end -}}
{{- $cpGrpcPort := include "ferrum-gateway.cpGrpcPort" . -}}
{{- $cpLoopback := or (hasPrefix "127." $cpBindHost) (eq $cpBindHost "::1") -}}
{{- $cpGrpcTls := $tlsAll.cpGrpc | default dict -}}
{{- $cpGrpcTlsSet := include "ferrum-gateway.serverTlsConfigured" (dict "root" . "surface" $cpGrpcTls "certSource" "FERRUM_CP_GRPC_TLS_CERT_SOURCE" "keySource" "FERRUM_CP_GRPC_TLS_KEY_SOURCE") -}}
{{- if and (ne ($cpGrpcPort | toString) "0") (not $cpLoopback) (not $cpGrpcTlsSet) (not $grpc.allowPlaintext) -}}
{{- fail (printf "mode=cp hard-fails on a non-loopback PLAINTEXT gRPC bind (%s:%v). Set one of: gRPC TLS (tls.cpGrpc Secret or a complete FERRUM_CP_GRPC_TLS_{CERT,KEY}_SOURCE pair), a loopback cp.grpcBindAddress (127.0.0.1), or grpc.allowPlaintext=true to explicitly permit plaintext config sync (dev only; pair with a NetworkPolicy)." $cpBind $cpGrpcPort) -}}
{{- end -}}
{{/* A ClusterIP Service routes to the pod IP + targetPort, never the container's
     loopback, so a loopback-bound CP gRPC listener published through the Service
     black-holes every DP connection even though Helm rendered cleanly. */}}
{{- $cpSvc := .Values.cp.service | default dict -}}
{{- if and $cpSvc.enabled $cpLoopback (ne ($cpGrpcPort | toString) "0") -}}
{{- fail (printf "cp.service.enabled=true is unreachable with a loopback cp.grpcBindAddress (%s): a Service routes to the pod IP, not the container loopback, so DPs cannot reach the CP gRPC listener. Bind a non-loopback address (0.0.0.0 or ::) with gRPC TLS or grpc.allowPlaintext, or set cp.service.enabled=false." $cpBind) -}}
{{- end -}}
{{- end -}}
{{- if eq $mode "dp" -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "grpc.jwtSecret" "source" ($grpc.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_CP_DP_GRPC_JWT_SECRET") -}}
{{- if not .Values.dp.cpGrpcUrls -}}
{{- fail "dp.cpGrpcUrls is required for mode=dp (comma-separated CP gRPC URLs, e.g. https://ferrum-cp:50051)" -}}
{{- end -}}
{{/* The DP runtime rejects any CP URL whose scheme is not http/https/grpc/grpcs
     (case-insensitive), so catch typos and schemeless host:port before boot. */}}
{{- $badScheme := include "ferrum-gateway.dpInvalidSchemeUrl" . -}}
{{- if $badScheme -}}
{{- fail (printf "dp.cpGrpcUrls entry %q has an unsupported scheme; each CP URL must start with https:// (TLS, recommended) or http:///grpc:// (plaintext, loopback or grpc.allowPlaintext only). The binary rejects other schemes at startup." $badScheme) -}}
{{- end -}}
{{/* The DP runtime rejects a CP URL with an empty host (e.g. "https://") even
     though it is not plaintext, so validate host presence for every scheme. */}}
{{- $hostless := include "ferrum-gateway.dpHostlessUrl" . -}}
{{- if $hostless -}}
{{- fail (printf "dp.cpGrpcUrls entry %q has no host; the DP runtime rejects a CP URL with an empty host at startup. Provide scheme://host[:port] (e.g. https://ferrum-cp:50051)." $hostless) -}}
{{- end -}}
{{/* The binary rejects a non-loopback PLAINTEXT (http://) CP URL unless
     FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true (src/config/env_config.rs). */}}
{{- if not $grpc.allowPlaintext -}}
{{- $badUrl := include "ferrum-gateway.dpPlaintextUrl" . -}}
{{- if $badUrl -}}
{{- fail (printf "dp.cpGrpcUrls entry %q is PLAINTEXT to a non-loopback host; the DP JWT and config data would cross the network in cleartext. Use an https:// URL (with tls.dpGrpc for CA pinning), target a loopback host, or set grpc.allowPlaintext=true to explicitly permit plaintext config sync (dev only)." $badUrl) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $mode "file" -}}
{{- $file := .Values.file | default dict -}}
{{- if and (not $file.inlineConfig) (not $file.existingConfigMap) -}}
{{- fail "mode=file requires either file.inlineConfig or file.existingConfigMap" -}}
{{- end -}}
{{- if and $file.inlineConfig $file.existingConfigMap -}}
{{- fail "set only one of file.inlineConfig or file.existingConfigMap, not both" -}}
{{- end -}}
{{- end -}}
{{/* Admin bind safety. The binary binds admin to loopback by default. */}}
{{- $admin := .Values.admin | default dict -}}
{{- $bind := $admin.bindAddress | default "" -}}
{{- $adminAllowedCidrs := $admin.allowedCidrs | default "" -}}
{{/* CidrSet::parse_strict rejects every malformed IP/CIDR and empty comma
     segment. Validate before treating the allowlist as a plaintext guard so a
     typo cannot render successfully and then CrashLoop during mode startup. */}}
{{- if trim $adminAllowedCidrs -}}
{{- range $raw := splitList "," $adminAllowedCidrs -}}
{{- $entry := trim $raw -}}
{{- if or (contains "[" $entry) (contains "]" $entry) -}}
{{- fail (printf "admin.allowedCidrs entry %q uses bracketed IPv6 syntax, but the runtime requires bare IPv6 addresses/CIDRs (for example fd00::/8 or ::1/128)" $entry) -}}
{{- end -}}
{{- if not (include "ferrum-gateway.validAdminCidrEntry" $entry) -}}
{{- $display := $entry | default "<empty>" -}}
{{- fail (printf "admin.allowedCidrs entry %q is not a valid IP address or CIDR; expected forms such as 10.0.0.0/8, 192.168.1.1, ::1, or fd00::/8" $display) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{/* EnvConfig::validate() rejects any FERRUM_ADMIN_BIND_ADDRESS that is not an
     IP literal (src/config/env_config.rs), so a hostname (localhost,
     admin.internal, host.docker.internal, ...) boots and then exits. Reject any
     non-IP value at render with the IP to use instead. */}}
{{- if eq (lower $bind) "localhost" -}}
{{- fail "admin.bindAddress=localhost is rejected: the binary requires FERRUM_ADMIN_BIND_ADDRESS to be an IP literal and exits otherwise. Use 127.0.0.1 (or ::1) for the loopback default, or 0.0.0.0/:: to expose admin through a Service." -}}
{{- end -}}
{{- if and $bind (not (include "ferrum-gateway.isIpLiteral" $bind)) -}}
{{- fail (printf "admin.bindAddress=%q is not an IP literal: the binary requires FERRUM_ADMIN_BIND_ADDRESS to parse as an IP address (e.g. 127.0.0.1, ::1, 0.0.0.0, ::) and exits otherwise. Use an IP literal, not a hostname." $bind) -}}
{{- end -}}
{{- $normalizedBind := $bind | trimPrefix "[" | trimSuffix "]" -}}
{{- $loopback := or (eq $normalizedBind "") (eq $normalizedBind "::1") (regexMatch "^127\\." $normalizedBind) -}}
{{- $adminHttpPort := include "ferrum-gateway.adminHttpPort" . -}}
{{- $adminSvc := $admin.service | default dict -}}
{{- if and $adminSvc.enabled $loopback -}}
{{- fail "admin.service.enabled=true requires admin.bindAddress to be a non-loopback address (e.g. 0.0.0.0 or ::); a loopback-bound admin listener is not reachable through a Service" -}}
{{- end -}}
{{- if and (not $loopback) (or (eq $mode "database") (eq $mode "cp")) (ne ($adminHttpPort | toString) "0") -}}
{{- $allowedCidrs := trim $adminAllowedCidrs -}}
{{- $permitsAll := include "ferrum-gateway.adminAllowlistPermitsAll" $allowedCidrs -}}
{{- $hasEffectiveAllowlist := and $allowedCidrs (not $permitsAll) -}}
{{- $hasProtection := or $hasEffectiveAllowlist $admin.allowInsecureHttp -}}
{{- if not $hasProtection -}}
{{- if $permitsAll -}}
{{- fail "admin.allowedCidrs permits every address in an IP family (for example via /0, an IPv4-mapped /96, or a full-coverage CIDR union), which does not restrict a non-loopback plaintext admin listener. Use a narrower allowlist, TLS-only admin with ports.adminHttp=0, or admin.allowInsecureHttp=true for local development." -}}
{{- end -}}
{{- fail (printf "mode=%s hard-fails on a non-loopback plaintext admin bind. Set one of: admin.allowedCidrs, admin TLS (tls.admin Secret or complete FERRUM_ADMIN_TLS_{CERT,KEY}_SOURCE pair + ports.adminHttp=0), or admin.allowInsecureHttp=true with a NetworkPolicy" $mode) -}}
{{- end -}}
{{- end -}}
{{/* The admin accept loop applies allowedCidrs to in-pod probes like every other
     source. Require the source address the listener actually observes whenever
     at least one computed handler is active. */}}
{{- $probes := .Values.probes | default dict -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $defaultLiveProbe := and (or $startup.enabled $liveness.enabled) (not ($liveness.override | default dict)) -}}
{{- $defaultReadyProbe := and $readiness.enabled (not ($readiness.override | default dict)) -}}
{{/* ports.adminHttp=0 switches the computed exec probes to `health --tls`
     (admin HTTPS :9443), but the serving modes only start admin HTTPS when admin
     TLS material is configured (src/modes/*.rs). Without it there is no admin
     listener and the kubelet restart-loops the pod. Require admin TLS. */}}
{{- if and (eq ($adminHttpPort | toString) "0") (or $defaultLiveProbe $defaultReadyProbe) -}}
{{- $adminTls := $tlsAll.admin | default dict -}}
{{- $adminTlsSet := include "ferrum-gateway.serverTlsConfigured" (dict "root" . "surface" $adminTls "certSource" "FERRUM_ADMIN_TLS_CERT_SOURCE" "keySource" "FERRUM_ADMIN_TLS_KEY_SOURCE") -}}
{{/* Both admin ports disabled means no admin listener at all, yet the computed
     probes still run `health --tls` and dial a nonexistent admin port, so the
     kubelet restart-loops the pod. Require an active admin listener. */}}
{{- if eq (include "ferrum-gateway.adminHttpsPort" . | toString) "0" -}}
{{- fail "ports.adminHttp=0 and ports.adminHttps=0 disable every admin listener, but the computed probes still run `ferrum-edge health` against the admin API and would restart-loop the pod. Enable an admin listener (ports.adminHttp or ports.adminHttps), or override/disable every computed probe (probes.liveness.override + probes.readiness.override, or disable startup/liveness/readiness)." -}}
{{- end -}}
{{- if not $adminTlsSet -}}
{{- fail "ports.adminHttp=0 makes the computed probes target admin HTTPS (:9443), but admin HTTPS only serves when a complete cert/key pair is configured. Set tls.admin.enabled=true with tls.admin.secretName, supply FERRUM_ADMIN_TLS_CERT_SOURCE + FERRUM_ADMIN_TLS_KEY_SOURCE, or override/disable every computed probe (probes.liveness.override + probes.readiness.override, or disable startup/liveness/readiness)." -}}
{{- end -}}
{{/* Admin mTLS configured either by the chart's Secret key or through the
     supported *_SOURCE env makes the HTTPS listener demand a client certificate.
     The computed CLI probes cannot present one, so require custom handlers. */}}
{{- $adminClientCaSource := include "ferrum-gateway.tlsSourceConfigured" (dict "root" . "name" "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE") -}}
{{- $adminClientCaPath := and $adminTls.enabled $adminTls.secretName $adminTls.clientCaKey -}}
{{- if or $adminClientCaPath $adminClientCaSource -}}
{{- fail "ports.adminHttp=0 with admin mTLS (tls.admin.clientCaKey or FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE set) makes the admin HTTPS listener require a client certificate, but the computed exec probes run `ferrum-edge health --tls` and cannot present one, so they fail the handshake and restart-loop the pod. Override every computed probe with a handler that presents a client cert (probes.liveness.override + probes.readiness.override), disable startup/liveness/readiness, or keep a plaintext loopback admin listener (ports.adminHttp>0)." -}}
{{- end -}}
{{- end -}}
{{- if and (trim $adminAllowedCidrs) (or $defaultLiveProbe $defaultReadyProbe) -}}
{{/* The dial destination and observed TCP source normally match. Linux is the
     exception for a concrete 127/8 destination: it selects 127.0.0.1 as source.
     Validate the observed source rather than assuming the dial host is the peer. */}}
{{- $probeHost := include "ferrum-gateway.probeHost" . -}}
{{- $probeSource := include "ferrum-gateway.probeSource" . -}}
{{- $probeIsV6 := contains ":" $probeSource -}}
{{- $hasProbeSource := include "ferrum-gateway.adminAllowlistContainsIp" (dict "ip" $probeSource "allowedCidrs" $adminAllowedCidrs) -}}
{{- if not $hasProbeSource -}}
{{- $probeCidr := ternary (printf "%s/128" $probeSource) (printf "%s/32" $probeSource) $probeIsV6 -}}
{{- fail (printf "admin.allowedCidrs must include %s (or bare %s) while the default exec probes are enabled; the computed exec probes dial admin host %s from source %s and the admin TCP allowlist otherwise drops the in-pod health checks. Add the exact probe source (or a covering CIDR) or override/disable every computed probe handler." $probeCidr $probeSource $probeHost $probeSource) -}}
{{- end -}}
{{- end -}}
{{/* Graceful shutdown: give the pod time to drain plus the ~5s cleanup window.
     Use presence (not truthiness) checks so an intentional drain of 0 (skip
     draining, per docs/configuration.md) is honored instead of dropped. A null
     shutdownDrainSeconds omits FERRUM_SHUTDOWN_DRAIN_SECONDS, so the binary
     falls back to its 30s default (shutdown_drain_seconds default in
     src/config/env_config.rs); validate the grace period against that default
     rather than skipping the guard, or a lowered grace SIGKILLs the pod
     mid-drain. */}}
{{- $drain := .Values.shutdownDrainSeconds -}}
{{- $effectiveDrain := 30 -}}
{{- if not (kindIs "invalid" $drain) -}}{{- $effectiveDrain = int $drain -}}{{- end -}}
{{- $grace := .Values.terminationGracePeriodSeconds -}}
{{- if and (not (kindIs "invalid" $grace)) (lt (int $grace) (add $effectiveDrain 5)) -}}
{{- fail (printf "terminationGracePeriodSeconds (%d) must be at least the effective shutdownDrainSeconds + 5s cleanup (%d); a null shutdownDrainSeconds uses the binary's 30s default" (int $grace) (add $effectiveDrain 5)) -}}
{{- end -}}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Env assembly.
--------------------------------------------------------------------------- */}}
{{/* Canonical set of every FERRUM_* env the chart renders from first-class
     values. Overriding any of these through env/extraEnv desyncs the rendered
     probes, Services, ports, or Secret wiring from the running process, so both
     env passthroughs reject them. Keep this list the single source of truth. */}}
{{- define "ferrum-gateway.reservedEnv" -}}
FERRUM_MODE FERRUM_NAMESPACE FERRUM_DB_TYPE FERRUM_DB_URL FERRUM_ADMIN_JWT_SECRET FERRUM_CP_DP_GRPC_JWT_SECRET FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT FERRUM_DP_CP_GRPC_URLS FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS FERRUM_CP_GRPC_LISTEN_ADDR FERRUM_CP_NAMESPACES FERRUM_CP_REQUIRE_NAMESPACE_CLAIM FERRUM_FILE_CONFIG_PATH FERRUM_PROXY_HTTP_PORT FERRUM_PROXY_HTTPS_PORT FERRUM_ADMIN_HTTP_PORT FERRUM_ADMIN_HTTPS_PORT FERRUM_ADMIN_BIND_ADDRESS FERRUM_ADMIN_ALLOWED_CIDRS FERRUM_ALLOW_INSECURE_ADMIN_HTTP FERRUM_SHUTDOWN_DRAIN_SECONDS FERRUM_FRONTEND_TLS_CERT_PATH FERRUM_FRONTEND_TLS_KEY_PATH FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH FERRUM_ADMIN_TLS_CERT_PATH FERRUM_ADMIN_TLS_KEY_PATH FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH FERRUM_BACKEND_TLS_CLIENT_CERT_PATH FERRUM_BACKEND_TLS_CLIENT_KEY_PATH FERRUM_CP_GRPC_TLS_CERT_PATH FERRUM_CP_GRPC_TLS_KEY_PATH FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH FERRUM_DP_GRPC_TLS_CA_CERT_PATH FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH
{{- end -}}

{{- define "ferrum-gateway.modeEnv" -}}
{{- $mode := .Values.mode -}}
- name: FERRUM_MODE
  value: {{ $mode | quote }}
{{- if .Values.ferrumNamespace }}
- name: FERRUM_NAMESPACE
  value: {{ .Values.ferrumNamespace | quote }}
{{- end }}
{{- if or (eq $mode "database") (eq $mode "cp") }}
- name: FERRUM_DB_TYPE
  value: {{ .Values.database.type | quote }}
{{- $dbUrlFileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" . "envName" "FERRUM_DB_URL") | int }}
{{- if eq $dbUrlFileCount 0 }}
{{ include "ferrum-gateway.renderDbUrlEnv" . }}
{{- end }}
{{- end }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.admin.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_ADMIN_JWT_SECRET" "source" (.Values.admin.jwtSecret | default dict) "defaultKey" "admin-jwt-secret") }}
{{- end }}
{{- if eq $mode "cp" }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.grpc.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" (.Values.grpc.jwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end }}
- name: FERRUM_CP_GRPC_LISTEN_ADDR
  value: {{ include "ferrum-gateway.cpGrpcListenAddr" . | quote }}
{{- if .Values.cp.namespaces }}
- name: FERRUM_CP_NAMESPACES
  value: {{ .Values.cp.namespaces | quote }}
{{- end }}
{{- if .Values.cp.requireNamespaceClaim }}
- name: FERRUM_CP_REQUIRE_NAMESPACE_CLAIM
  value: "true"
{{- end }}
{{- end }}
{{- if eq $mode "dp" }}
- name: FERRUM_DP_CP_GRPC_URLS
  value: {{ .Values.dp.cpGrpcUrls | quote }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.grpc.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" (.Values.grpc.jwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end }}
{{/* Presence, not truthiness: failoverPrimaryRetrySeconds=0 disables primary-CP
     retry and must render, else the binary falls back to its 300s default. An
     empty string means "unset" (the value default) and is also omitted. */}}
{{- if and (not (kindIs "invalid" .Values.dp.failoverPrimaryRetrySeconds)) (ne (.Values.dp.failoverPrimaryRetrySeconds | toString) "") }}
- name: FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS
  value: {{ .Values.dp.failoverPrimaryRetrySeconds | quote }}
{{- end }}
{{- end }}
{{- if and (or (eq $mode "cp") (eq $mode "dp")) (.Values.grpc | default dict).allowPlaintext }}
- name: FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT
  value: "true"
{{- end }}
{{- if eq $mode "file" }}
- name: FERRUM_FILE_CONFIG_PATH
  value: {{ include "ferrum-gateway.fileConfigPath" . | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.cpGrpcPort" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "cpGrpc" -}}{{- $ports.cpGrpc -}}{{- else -}}50051{{- end -}}
{{- end -}}

{{/* FERRUM_CP_GRPC_LISTEN_ADDR. IPv6 literal binds MUST be bracketed: the runtime
     parses this with SocketAddr::parse (cp_grpc_socket_addr), which requires
     [::]:50051, not :::50051. Port 0 keeps the listener disabled per the runtime. */}}
{{- define "ferrum-gateway.cpGrpcListenAddr" -}}
{{- $host := .Values.cp.grpcBindAddress | default "0.0.0.0" -}}
{{- $host = $host | trimPrefix "[" | trimSuffix "]" -}}
{{- if contains ":" $host -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- printf "%s:%v" $host (include "ferrum-gateway.cpGrpcPort" .) -}}
{{- end -}}

{{/* Proxy / admin port + bind env. Ports set to 0 disable the listener. */}}
{{- define "ferrum-gateway.portEnv" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "proxyHttp" }}
- name: FERRUM_PROXY_HTTP_PORT
  value: {{ $ports.proxyHttp | quote }}
{{- end }}
{{- if hasKey $ports "proxyHttps" }}
- name: FERRUM_PROXY_HTTPS_PORT
  value: {{ $ports.proxyHttps | quote }}
{{- end }}
{{- if hasKey $ports "adminHttp" }}
- name: FERRUM_ADMIN_HTTP_PORT
  value: {{ $ports.adminHttp | quote }}
{{- end }}
{{- if hasKey $ports "adminHttps" }}
- name: FERRUM_ADMIN_HTTPS_PORT
  value: {{ $ports.adminHttps | quote }}
{{- end }}
{{- $admin := .Values.admin | default dict }}
{{- if $admin.bindAddress }}
- name: FERRUM_ADMIN_BIND_ADDRESS
  value: {{ $admin.bindAddress | quote }}
{{- end }}
{{- if $admin.allowedCidrs }}
- name: FERRUM_ADMIN_ALLOWED_CIDRS
  value: {{ $admin.allowedCidrs | quote }}
{{- end }}
{{- if $admin.allowInsecureHttp }}
- name: FERRUM_ALLOW_INSECURE_ADMIN_HTTP
  value: "true"
{{- end }}
{{- end -}}

{{/* Shutdown drain env (pairs with terminationGracePeriodSeconds). Presence, not
     truthiness: a documented 0 (skip draining) must still emit the env, else the
     binary falls back to its 30s default. */}}
{{- define "ferrum-gateway.shutdownEnv" -}}
{{- if not (kindIs "invalid" .Values.shutdownDrainSeconds) }}
- name: FERRUM_SHUTDOWN_DRAIN_SECONDS
  value: {{ .Values.shutdownDrainSeconds | quote }}
{{- end }}
{{- end -}}

{{/* TLS path env for each enabled surface. */}}
{{- define "ferrum-gateway.tlsEnv" -}}
{{- $tls := .Values.tls | default dict -}}
{{- $f := $tls.frontend | default dict -}}
{{- if and $f.enabled $f.secretName }}
- name: FERRUM_FRONTEND_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) ($f.certKey | default "tls.crt") | quote }}
- name: FERRUM_FRONTEND_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) ($f.keyKey | default "tls.key") | quote }}
{{- if $f.clientCaKey }}
- name: FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) $f.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- $a := $tls.admin | default dict -}}
{{- if and $a.enabled $a.secretName }}
- name: FERRUM_ADMIN_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) ($a.certKey | default "tls.crt") | quote }}
- name: FERRUM_ADMIN_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) ($a.keyKey | default "tls.key") | quote }}
{{- if $a.clientCaKey }}
- name: FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) $a.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- $b := $tls.backend | default dict -}}
{{- if and $b.enabled $b.secretName }}
- name: FERRUM_BACKEND_TLS_CLIENT_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($b.mountPath | default "/etc/ferrum/tls/backend")) ($b.clientCertKey | default "tls.crt") | quote }}
- name: FERRUM_BACKEND_TLS_CLIENT_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($b.mountPath | default "/etc/ferrum/tls/backend")) ($b.clientKeyKey | default "tls.key") | quote }}
{{- end }}
{{- if eq .Values.mode "cp" }}
{{- $cg := $tls.cpGrpc | default dict -}}
{{- if and $cg.enabled $cg.secretName }}
- name: FERRUM_CP_GRPC_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) ($cg.certKey | default "tls.crt") | quote }}
- name: FERRUM_CP_GRPC_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) ($cg.keyKey | default "tls.key") | quote }}
{{- if $cg.clientCaKey }}
- name: FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) $cg.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- if eq .Values.mode "dp" }}
{{- $dg := $tls.dpGrpc | default dict -}}
{{- if and $dg.enabled $dg.secretName }}
- name: FERRUM_DP_GRPC_TLS_CA_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) ($dg.caKey | default "ca.crt") | quote }}
{{- if $dg.clientCertKey }}
- name: FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) $dg.clientCertKey | quote }}
- name: FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) ($dg.clientKeyKey | default "tls.key") | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* External-secret _FILE-suffix env: mount a Secret key and point <VAR>_FILE at it. */}}
{{- define "ferrum-gateway.secretFileEnv" -}}
{{- range .Values.secretFileMounts }}
- name: {{ printf "%s_FILE" .name }}
  value: {{ printf "%s/%s" (trimSuffix "/" (.mountPath | default (printf "/etc/ferrum/secret-files/%s" (lower .name)))) (.secretKey | default "value") | quote }}
{{- end }}
{{- end -}}

{{/* User-supplied simple string env, with reserved keys rejected. The same
     reserved set is enforced against extraEnv (list form) so neither passthrough
     can shadow a chart-managed FERRUM_* var. */}}
{{- define "ferrum-gateway.userEnv" -}}
{{- $reserved := splitList " " (include "ferrum-gateway.reservedEnv" .) -}}
{{/* External-secret resolver suffixes (_VAULT/_AWS/_AZURE/_GCP/_FILE, see
     src/secrets/registry.rs) of a chart-managed base var resolve INTO that base
     var before config load. When the chart already renders the base directly
     (existingSecret / valueFrom / value / structured), a user-supplied suffixed
     source makes resolve_all_env_secrets() see multiple sources for one base key
     and abort startup ("Multiple secret sources configured for ..."). Reserve
     every suffixed form of every chart-managed FERRUM_* var so env/extraEnv
     cannot introduce a second, conflicting source the render guards can't see. */}}
{{- $suffixes := list "_VAULT" "_AWS" "_AZURE" "_GCP" "_FILE" -}}
{{- range $name := (splitList " " (include "ferrum-gateway.reservedEnv" .)) -}}
{{- range $sfx := $suffixes -}}
{{- $reserved = append $reserved (printf "%s%s" $name $sfx) -}}
{{- end -}}
{{- end -}}
{{/* secretFileMounts emit <name>_FILE env vars later in the container spec. Both
     the generated name AND its base must be reserved: setting the base directly
     alongside its _FILE source makes resolve_all_env_secrets() reject the two
     providers for one key. (Mount names may be any FERRUM_* var.) */}}
{{- range .Values.secretFileMounts -}}
{{- if .name -}}
{{- $reserved = append $reserved .name -}}
{{- $reserved = append $reserved (printf "%s_FILE" .name) -}}
{{- end -}}
{{- end -}}
{{- range $entry := .Values.extraEnv }}
{{- if has $entry.name $reserved }}
{{- fail (printf "extraEnv entry %s is managed by first-class chart values; set it through the dedicated value instead of extraEnv" $entry.name) }}
{{- end }}
{{- end }}
{{- range $name, $value := .Values.env }}
{{- if has $name $reserved }}
{{- fail (printf "env.%s is managed by first-class chart values; set it through the dedicated value instead of env" $name) }}
{{- end }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Volumes / mounts.
--------------------------------------------------------------------------- */}}
{{- define "ferrum-gateway.tlsVolumes" -}}
{{- $tls := .Values.tls | default dict -}}
{{- range $key, $section := $tls }}
{{- $s := $section | default dict }}
{{- if and $s.enabled $s.secretName }}
{{- if or (not (has $key (list "cpGrpc" "dpGrpc"))) (and (eq $key "cpGrpc") (eq $.Values.mode "cp")) (and (eq $key "dpGrpc") (eq $.Values.mode "dp")) }}
- name: {{ printf "tls-%s" ($key | kebabcase) }}
  secret:
    secretName: {{ $s.secretName | quote }}
    defaultMode: {{ $.Values.secretVolumeDefaultMode | default 288 }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.tlsMounts" -}}
{{- $tls := .Values.tls | default dict -}}
{{- $defaults := dict "frontend" "/etc/ferrum/tls/frontend" "admin" "/etc/ferrum/tls/admin" "backend" "/etc/ferrum/tls/backend" "cpGrpc" "/etc/ferrum/tls/cp-grpc" "dpGrpc" "/etc/ferrum/tls/dp-grpc" -}}
{{- range $key, $section := $tls }}
{{- $s := $section | default dict }}
{{- if and $s.enabled $s.secretName }}
{{- if or (not (has $key (list "cpGrpc" "dpGrpc"))) (and (eq $key "cpGrpc") (eq $.Values.mode "cp")) (and (eq $key "dpGrpc") (eq $.Values.mode "dp")) }}
- name: {{ printf "tls-%s" ($key | kebabcase) }}
  mountPath: {{ $s.mountPath | default (get $defaults $key) | quote }}
  readOnly: true
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.secretFileVolumes" -}}
{{- range $i, $m := .Values.secretFileMounts }}
- name: {{ printf "secret-file-%d" $i }}
  secret:
    secretName: {{ $m.secretName | quote }}
    defaultMode: {{ $.Values.secretVolumeDefaultMode | default 288 }}
    items:
      - key: {{ ($m.secretKey | default "value") | quote }}
        path: {{ ($m.secretKey | default "value") | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.secretFileMounts" -}}
{{- range $i, $m := .Values.secretFileMounts }}
- name: {{ printf "secret-file-%d" $i }}
  mountPath: {{ ($m.mountPath | default (printf "/etc/ferrum/secret-files/%s" (lower $m.name))) | quote }}
  readOnly: true
{{- end }}
{{- end -}}
