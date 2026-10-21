#!/usr/bin/env bash
# Literal process dispatch for the trusted Cross policy; Python owns the plan.
set -euo pipefail
mode="${GATEWAY_REGRESSION_OPERATION:?}"
case "$mode" in
    image-inspect)
        timeout --signal=TERM --kill-after=2s 10s docker image inspect "$GATEWAY_REGRESSION_IMAGE"
        ;;
    image-passwd)
        [[ "$GATEWAY_REGRESSION_RUN_ID" =~ ^[0-9a-f]{32}$ ]] || exit 2
        case "$GATEWAY_REGRESSION_ROLE" in candidate|baseline) ;; *) exit 2 ;; esac
        name="gateway-regression-$GATEWAY_REGRESSION_RUN_ID-identity-$GATEWAY_REGRESSION_ROLE"
        trap 'timeout --signal=TERM --kill-after=2s 10s docker rm -f "$name" >/dev/null' EXIT
        timeout --signal=TERM --kill-after=2s 10s docker create --name "$name" "$GATEWAY_REGRESSION_IMAGE" >/dev/null
        timeout --signal=TERM --kill-after=2s 10s docker cp "$name:/etc/passwd" -
        ;;
    identity-remove)
        [[ "$GATEWAY_REGRESSION_RUN_ID" =~ ^[0-9a-f]{32}$ ]] || exit 2
        case "$GATEWAY_REGRESSION_ROLE" in candidate|baseline) ;; *) exit 2 ;; esac
        name="gateway-regression-$GATEWAY_REGRESSION_RUN_ID-identity-$GATEWAY_REGRESSION_ROLE"
        timeout --signal=TERM --kill-after=2s 10s docker rm -f "$name" >/dev/null 2>&1 || true
        remaining=$(timeout --signal=TERM --kill-after=2s 10s docker ps --all --quiet --filter "name=^/$name$")
        [ -z "$remaining" ]
        ;;
    fixture-group)
        # Only the four paths created exclusively by this invocation.
        timeout --signal=TERM --kill-after=2s 10s sudo -n chgrp 65532 \
            "$GATEWAY_REGRESSION_FIXTURE/certs" "$GATEWAY_REGRESSION_FIXTURE/certs/ca.pem" \
            "$GATEWAY_REGRESSION_FIXTURE/certs/cert.pem" "$GATEWAY_REGRESSION_FIXTURE/certs/key.pem"
        ;;
    cleanup-session)
        sudo -n --preserve-env=H1_DIAGNOSTIC_SESSION,H1_DIAGNOSTIC_START_TICKS \
            timeout --signal=TERM --kill-after=1s 5s \
            python3 tests/performance/multi_protocol/h1_diagnostic_campaign.py cleanup-processes
        ;;
    container-logs|container-remove)
        name="gateway-regression-$GATEWAY_REGRESSION_RUN_ID-$GATEWAY_REGRESSION_ROLE"
        [[ "$name" =~ ^gateway-regression-[0-9a-f]{32}-(ferrum|ferrum-baseline)$ ]] || exit 2
        if [ "$mode" = container-logs ]; then
            timeout --signal=TERM --kill-after=2s 10s docker logs --timestamps "$name"
        else
            timeout --signal=TERM --kill-after=2s 10s docker rm -f "$name" >/dev/null 2>&1 || true
            remaining=$(timeout --signal=TERM --kill-after=2s 10s docker ps --all --quiet --filter "name=^/$name$")
            [ -z "$remaining" ]
        fi
        ;;
    tail-protocol)
        case "$GATEWAY_REGRESSION_PROTOCOL" in http1-tls|http2) ;; *) exit 2 ;; esac
        [[ "$GATEWAY_REGRESSION_PAIR" =~ ^[1-8]$ ]] || exit 2
        exec bash tests/performance/multi_protocol/run_gateway_protocol_bench.sh "$GATEWAY_REGRESSION_PROTOCOL" \
            --baseline-image "$GATEWAY_REGRESSION_BASELINE_IMAGE" --gateways ferrum \
            --payload-sizes 1048576 --duration 30 --concurrency 100 --pairs 1 --skip-direct \
            --tail-confirm-pair "$GATEWAY_REGRESSION_PAIR" --h2-window default \
            --grpc-client-connections pooled --experiment-manifest /dev/null --skip-build \
            --output-dir "$GATEWAY_REGRESSION_OUTPUT" --owned-run-id "$GATEWAY_REGRESSION_RUN_ID" \
            --regression-fixture-root "$GATEWAY_REGRESSION_FIXTURE"
        ;;
    protocol)
        case "$GATEWAY_REGRESSION_PROTOCOL" in http1-tls|http2) ;; *) exit 2 ;; esac
        exec bash tests/performance/multi_protocol/run_gateway_protocol_bench.sh "$GATEWAY_REGRESSION_PROTOCOL" \
            --baseline-image "$GATEWAY_REGRESSION_BASELINE_IMAGE" --gateways ferrum \
            --payload-sizes "10240 1048576 5242880" --duration 15 --concurrency 100 --pairs 4 \
            --h2-window default --grpc-client-connections pooled --experiment-manifest /dev/null --skip-build \
            --output-dir "$GATEWAY_REGRESSION_OUTPUT" --owned-run-id "$GATEWAY_REGRESSION_RUN_ID" \
            --regression-fixture-root "$GATEWAY_REGRESSION_FIXTURE"
        ;;
    *) exit 2 ;;
esac
