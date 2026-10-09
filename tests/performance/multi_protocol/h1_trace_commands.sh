#!/usr/bin/env bash
# Literal hosted execution inventory. No data field is an executable or script.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ ${RUNNER_OS:-} == Linux && ${RUNNER_ARCH:-} == X64 ]]
case "${H1_TRACE_ACTION:?}" in
  observer)
    [[ ${H1_TRACE_NETNS:?} =~ ^[1-9][0-9]{0,19}$ ]]
    case "${H1_TRACE_CAPACITY:?}" in 1|8192) ;; *) exit 2 ;; esac
    case "${H1_TRACE_FAULT:?}" in normal|missing-btf|missing-symbol) ;; *) exit 2 ;; esac
    if [[ ${H1_TRACE_DENIED:-false} == true ]]; then
      exec setpriv --reuid=65534 --regid=65534 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        /tmp/ferrum-h1-trace/observer /tmp/ferrum-h1-trace/observer.bpf.o \
        h1 "$H1_TRACE_NETNS" "$H1_TRACE_CAPACITY" "$H1_TRACE_FAULT"
    fi
    exec /tmp/ferrum-h1-trace/observer /tmp/ferrum-h1-trace/observer.bpf.o \
      h1 "$H1_TRACE_NETNS" "$H1_TRACE_CAPACITY" "$H1_TRACE_FAULT" ;;
  fixture)
    case "${H1_TRACE_MODE:?}" in syscalls|cpu|cpu-teardown) ;; *) exit 2 ;; esac
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --bounding-set=-all \
      --inh-caps=-all --ambient-caps=-all --no-new-privs \
      /tmp/ferrum-h1-trace/h1_trace_fixture "$H1_TRACE_MODE" ;;
  perf-record)
    [[ ${H1_TRACE_PID:?} =~ ^[1-9][0-9]{0,9}$ ]]
    [[ ${H1_TRACE_OUT:?} == /* ]]
    # Software clock, user stacks only; inherited threads and later children.
    exec /tmp/ferrum-h1-trace/perf record -e cpu-clock:uS --running-time -F 99 --clockid mono --call-graph dwarf,8192 \
      --mmap-pages=64 --timestamp --sample-cpu --buildid-all --buildid-mmap --no-buildid-cache \
      --all-user --user-callchains --no-bpf-event --strict-freq --synth=mmap --delay=-1 \
      --control="fifo:$H1_TRACE_OUT/perf.control,$H1_TRACE_OUT/perf.ack" \
      -p "$H1_TRACE_PID" -o "$H1_TRACE_OUT/perf.data" ;;
  perf-script)
    [[ ${H1_TRACE_OUT:?} == /* && ${H1_TRACE_SYMFS:?} == /* ]]
    exec /tmp/ferrum-h1-trace/perf script -i "$H1_TRACE_OUT/perf.data" --symfs "$H1_TRACE_SYMFS" \
      --ns --show-lost-events --show-task-events --show-mmap-events \
      -F comm,pid,tid,time,event,ip,sym,dso ;;
  perf-raw)
    [[ ${H1_TRACE_OUT:?} == /* ]]
    exec /tmp/ferrum-h1-trace/perf script -D -i "$H1_TRACE_OUT/perf.data" ;;
  perf-attributes)
    [[ ${H1_TRACE_OUT:?} == /* ]]
    exec /tmp/ferrum-h1-trace/perf evlist -v -i "$H1_TRACE_OUT/perf.data" ;;
  perf-header)
    [[ ${H1_TRACE_OUT:?} == /* ]]
    exec /tmp/ferrum-h1-trace/perf report --header-only --stdio -i "$H1_TRACE_OUT/perf.data" ;;
  perf-buildids)
    [[ ${H1_TRACE_OUT:?} == /* ]]
    exec /tmp/ferrum-h1-trace/perf buildid-list -i "$H1_TRACE_OUT/perf.data" ;;
  elf)
    [[ ${H1_TRACE_ELF:?} == /* ]]
    exec readelf -n -S "$H1_TRACE_ELF" ;;
  clang-version) exec clang-18 --version ;;
  cc-version) exec cc --version ;;
  readelf-version) exec readelf --version ;;
  perf-version) exec /tmp/ferrum-h1-trace/perf version --build-options ;;
  packages) exec dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' ;;
  package-origins) exec apt-cache policy linux-perf linux-tools-generic linux-tools-common libbpf-dev clang-18 libdw1t64 libunwind8 ;;
  tracefs) exec mount -t tracefs tracefs /sys/kernel/tracing ;;
  *) exit 2 ;;
esac
