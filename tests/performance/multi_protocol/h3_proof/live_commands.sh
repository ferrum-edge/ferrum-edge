#!/usr/bin/env bash
# Hosted-only literal execution inventory. Environment is data, never shell source.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ ${RUNNER_OS:-} == Linux && ${RUNNER_ARCH:-} == X64 ]]
case "${H3_LIVE_ACTION:?}" in
  docker-info) exec docker info --format '{{json .}}' ;;
  image-inspect)
    case "${H3_LIVE_IMAGE:?}" in
      ferrum-h3-live:qualified|docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb) ;;
      *) exit 2 ;;
    esac
    exec docker image inspect "$H3_LIVE_IMAGE" ;;
  buffers)
    exec sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304 \
      net.core.rmem_default=4194304 net.core.wmem_default=4194304 ;;
  tracefs) exec mount -t tracefs tracefs /sys/kernel/tracing ;;
  observer)
    case "${H3_LIVE_FAMILY:?}" in tx|rx|attach|lifetime|destroy|group|process|classic) ;; *) exit 2 ;; esac
    [[ ${H3_LIVE_NETNS:?} =~ ^[1-9][0-9]{0,19}$ ]]
    [[ ${H3_LIVE_CGROUP:?} =~ ^/sys/fs/cgroup/h3live[0-9]+\.slice$ ]]
    exec /tmp/ferrum-h3-live/build/observer /tmp/ferrum-h3-live/build/observer.bpf.o \
      "$H3_LIVE_FAMILY" "$H3_LIVE_NETNS" 4096 normal "$H3_LIVE_CGROUP" ;;
  backend|client)
    [[ ${H3_LIVE_CGROUP:?} =~ ^/sys/fs/cgroup/h3live[0-9]+\.slice/(backend|client)$ ]]
    printf '%s\n' "$$" > "$H3_LIVE_CGROUP/cgroup.procs"
    cd /tmp/ferrum-h3-live/runtime
    if [[ $H3_LIVE_ACTION == backend ]]; then
      export H3_PROFILE=4194304
      exec setpriv --reuid=65534 --regid=65534 --clear-groups \
        --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
        /tmp/ferrum-h3-live/build/proto_backend --h3-only
    fi
    case "${H3_LIVE_PAYLOAD:?}" in 10240|71680|512000|1048576|5242880) ;; *) exit 2 ;; esac
    case "${H3_LIVE_WORKERS:?}" in 200|100|50) ;; *) exit 2 ;; esac
    case "${H3_LIVE_DURATION:?}" in 2|30|40) ;; *) exit 2 ;; esac
    case "${H3_LIVE_TARGET:?}" in https://127.0.0.1:3445/echo|https://127.0.0.1:8443/echo) ;; *) exit 2 ;; esac
    exec setpriv --reuid=65534 --regid=65534 --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      /tmp/ferrum-h3-live/build/proto_bench http3 --target "$H3_LIVE_TARGET" \
      --duration "$H3_LIVE_DURATION" --concurrency "$H3_LIVE_WORKERS" \
      --payload-size "$H3_LIVE_PAYLOAD" --json ;;
  tls-fixture)
    [[ ${H3_LIVE_CGROUP:?} =~ ^/sys/fs/cgroup/h3live[0-9]+\.slice/(backend|client)$ ]]
    case "${H3_LIVE_MODE:?}" in certificates|backend|request) ;; *) exit 2 ;; esac
    printf '%s\n' "$$" > "$H3_LIVE_CGROUP/cgroup.procs"
    cd /tmp/ferrum-h3-live/runtime
    exec setpriv --reuid=65534 --regid=65534 --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      /tmp/ferrum-h3-live/build/h3_tls_fixture "$H3_LIVE_MODE" ;;
  create)
    [[ ${H3_LIVE_SLICE:?} =~ ^h3live[0-9]+\.slice$ ]]
    [[ ${H3_LIVE_NAME:?} =~ ^h3live[0-9]+$ ]]
    case "${H3_LIVE_ARM:?}" in
      ferrum)
        exec docker create --name "$H3_LIVE_NAME" --network host --cgroup-parent "$H3_LIVE_SLICE" \
          --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges:true \
          --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
          -v /tmp/ferrum-h3-live/runtime/certs:/certs:ro \
          -v /tmp/ferrum-h3-live/configs/ferrum.yaml:/config.yaml:ro \
          -e FERRUM_MODE=file -e FERRUM_FILE_CONFIG_PATH=/config.yaml \
          -e FERRUM_ENABLE_HTTP3=true -e FERRUM_PROXY_HTTP_PORT=0 \
          -e FERRUM_PROXY_HTTPS_PORT=8443 -e FERRUM_ADMIN_HTTP_PORT=9000 \
          -e FERRUM_FRONTEND_TLS_CERT_PATH=/certs/cert.pem -e FERRUM_FRONTEND_TLS_KEY_PATH=/certs/key.pem \
          -e FERRUM_LOG_LEVEL=info -e FERRUM_ADD_VIA_HEADER=false -e FERRUM_ADD_FORWARDED_HEADER=false \
          -e FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 -e FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
          -e FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0 -e FERRUM_MAX_CONNECTIONS=0 \
          -e FERRUM_POOL_WARMUP_ENABLED=true -e FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
          -e FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
          ferrum-h3-live:qualified ;;
      envoy|envoy-limit-4)
        [[ ${H3_LIVE_CPUS:?} =~ ^[1-9][0-9]?$ ]]
        exec docker create --name "$H3_LIVE_NAME" --network host --cgroup-parent "$H3_LIVE_SLICE" \
          --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges:true \
          --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
          -v /tmp/ferrum-h3-live/runtime/certs:/certs:ro \
          -v "/tmp/ferrum-h3-live/configs/$H3_LIVE_ARM.yaml:/etc/envoy/envoy.yaml:ro" \
          docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb \
          envoy -c /etc/envoy/envoy.yaml --concurrency "$H3_LIVE_CPUS" -l info --disable-hot-restart ;;
      *) exit 2 ;;
    esac ;;
  start|inspect|logs|stop|remove)
    [[ ${H3_LIVE_NAME:?} =~ ^h3live[0-9]+$ ]]
    case "$H3_LIVE_ACTION" in
      start) exec docker start "$H3_LIVE_NAME" ;;
      inspect) exec docker inspect "$H3_LIVE_NAME" ;;
      logs) exec docker logs --timestamps "$H3_LIVE_NAME" ;;
      stop) exec docker stop --time 10 "$H3_LIVE_NAME" ;;
      remove) exec docker rm -f "$H3_LIVE_NAME" ;;
    esac ;;
  envoy-binary)
    [[ ${H3_LIVE_NAME:?} =~ ^h3live[0-9]+$ ]]
    exec docker cp "$H3_LIVE_NAME:/usr/local/bin/envoy" /tmp/ferrum-h3-live/envoy-binary ;;
  envoy-build-id) exec readelf -n /tmp/ferrum-h3-live/envoy-binary ;;
  source) exec git rev-parse HEAD ;;
  tree) exec git rev-parse HEAD^{tree} ;;
  dirty) exec git status --porcelain --untracked-files=no ;;
  tools) exec dpkg-query -W -f='${binary:Package}\t${Version}\n' ;;
  *) exit 2 ;;
esac
