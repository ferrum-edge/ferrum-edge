// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "contract.h"

_Static_assert(sizeof(void *) == 8 && sizeof(struct msghdr) == 56, "native amd64 ABI");
_Static_assert(offsetof(struct msghdr, msg_flags) == 48, "native msg_flags");
_Static_assert(sizeof(struct mmsghdr) == 64 && offsetof(struct mmsghdr, msg_len) == 56, "native mmsghdr");
_Static_assert(sizeof(struct cmsghdr) == 16 && CMSG_ALIGN(1) == 8, "native cmsg");
static bool live, h1_mode;
static unsigned int lifecycle_rows, lifecycle_omitted;
static int rx_argc;
static volatile sig_atomic_t stopping;
static char verifier[256 * 1024];
// Linux include/linux/bpf_verifier.h: statistics without per-instruction traces.
// This is a logging flag, not a verifier/program/resource limit.
#define ATTACH_LOG_STATS 4U
static size_t log_bytes;
static bool log_truncated;

// Redact H1 address-shaped diagnostics before they reach disk, including when
// the supervisor dies before it can run its final evidence sanitizer.
static void h1_redact(char *data, size_t length)
{
    if (!h1_mode) return;
    for (size_t i = 0; i + 4 < length; i++) {
        bool prefix = data[i] == '0' && (data[i + 1] == 'x' || data[i + 1] == 'X');
        bool kernel = tolower((unsigned char)data[i]) == 'f' &&
                      tolower((unsigned char)data[i + 1]) == 'f' &&
                      tolower((unsigned char)data[i + 2]) == 'f' &&
                      tolower((unsigned char)data[i + 3]) == 'f';
        if (!prefix && !kernel) continue;
        size_t start = i + (prefix ? 2 : 0), end = start;
        while (end < length && isxdigit((unsigned char)data[end])) end++;
        if (end - start >= (prefix ? 8U : 16U)) {
            for (size_t j = start; j < end; j++) data[j] = 'x';
            i = end - 1;
        }
    }
}
static int logger(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    (void)level;
    char buf[4096];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) return n;
    size_t length = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
    if ((size_t)n >= sizeof(buf)) log_truncated = true;
    if (log_bytes + length > 512 * 1024) { log_truncated = true; return n; }
    log_bytes += length;
    // libbpf diagnostics are metadata/verifier instructions, never packet bytes.
    h1_redact(buf, length);
    fwrite(buf, 1, length, stderr);
    return n;
}
static unsigned long long now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}
static void stop_signal(int sig) { (void)sig; stopping = 1; }

// The small JSON strings passed here are fixed tokens, never arbitrary diagnostics.
static int unavailable(const char *status, const char *stage, int error)
{
    printf("{\"phase\":\"ready\",\"status\":\"%s\",\"reason\":\"%s\","
           "\"errno\":%d,\"verifier_log_truncated\":%s}\n",
           status, stage, error, log_truncated ? "true" : "false");
    fflush(stdout);
    return strcmp(status, "error") == 0 ? 1 : 0;
}
static const struct btf_type *resolve(const struct btf *b, __u32 id)
{
    const struct btf_type *t = btf__type_by_id(b, id);
    for (int i = 0; t && i < 16; i++) {
        if (!btf_is_mod(t) && !btf_is_typedef(t) && !btf_is_type_tag(t)) return t;
        t = btf__type_by_id(b, t->type);
    }
    return NULL;
}
static bool pointer_to(const struct btf *b, __u32 id, const char *name)
{
    const struct btf_type *t = resolve(b, id);
    if (!t || !btf_is_ptr(t)) return false;
    t = resolve(b, t->type);
    return t && btf_is_struct(t) && strcmp(btf__name_by_offset(b, t->name_off), name) == 0;
}
static bool integer(const struct btf *b, __u32 id, unsigned int size)
{
    const struct btf_type *t = resolve(b, id);
    return t && btf_is_int(t) && t->size == size;
}
struct site { const char *name; int argc; const char *args[5]; const char *ret; };
static const struct site h1_sites[] = {
    {"tcp_sendmsg", 3, {"sock", "msghdr", "8"}, "4"},
    {"tcp_recvmsg", 5, {"sock", "msghdr", "8", "4", "int_ptr"}, "4"},
};
static const struct site tx_sites[] = {
    {"udp_sendmsg", 3, {"sock", "msghdr", "8"}, "4"},
    {"udp_send_skb", 3, {"sk_buff", "flowi4", "inet_cork"}, "4"},
};
static const struct site rx_sites[] = {
    // Only the first argument is consumed; accept four/five-argument variants.
    {"udp_recvmsg", -1, {"sock", "msghdr", "8", "4"}, "4"},
};
static const struct site attach_sites[] = {
    {"reuseport_attach_prog", 2, {"sock", "bpf_prog"}, "4"},
};
static const struct site lifetime_sites[] = {
    {"inet_create", 4, {"net", "socket", "4", "4"}, "4"},
    {"inet_bind", 3, {"socket", "bind_address", "4"}, "4"},
};
static const struct site destroy_sites[] = {
    {"udp_destroy_sock", 1, {"sock"}, "void"},
    {"udp_sendmsg", 3, {"sock", "msghdr", "8"}, "4"},
    {"udp_recvmsg", -1, {"sock", "msghdr", "8", "4"}, "4"},
};
static const struct site group_sites[] = {
    {"reuseport_alloc", 2, {"sock", "1"}, "4"},
    {"reuseport_add_sock", 3, {"sock", "sock", "1"}, "4"},
    {"reuseport_detach_sock", 1, {"sock"}, "void"},
    {"reuseport_detach_prog", 1, {"sock"}, "4"},
};
static const struct site classic_sites[] = {
    {"reuseport_select_sock", 4, {"sock", "4", "sk_buff", "4"}, "sock"},
    {"run_bpf_filter", 5, {"sock_reuseport", "2", "bpf_prog", "sk_buff", "4"}, "sock"},
    {"reuseport_attach_prog", 2, {"sock", "bpf_prog"}, "4"},
    {"inet_bind", 3, {"socket", "bind_address", "4"}, "4"},
};
static bool matches(const struct btf *btf, __u32 type, const char *spec)
{
    // Linux 7.0 uses sockaddr_unsized for this unused inet_bind argument.
    // The probes consume only the socket and return code. Keep the exact
    // pointer identities, argument count, length and return checks enforced.
    if (!strcmp(spec, "bind_address"))
        return pointer_to(btf, type, "sockaddr") || pointer_to(btf, type, "sockaddr_unsized");
    if (!strcmp(spec, "int_ptr")) {
        const struct btf_type *t = resolve(btf, type);
        return t && btf_is_ptr(t) && integer(btf, t->type, 4);
    }
    if (!strcmp(spec, "void")) return type == 0;
    if (spec[0] >= '0' && spec[0] <= '9') return integer(btf, type, (unsigned int)atoi(spec));
    return pointer_to(btf, type, spec);
}
static int check_site(const struct btf *b, const struct site *s)
{
    int id = btf__find_by_name_kind(b, s->name, BTF_KIND_FUNC);
    if (id < 0) { fprintf(stderr, "missing BTF function: %s\n", s->name); return ENOENT; }
    const struct btf_type *f = btf__type_by_id(b, (__u32)id);
    const struct btf_type *p = btf__type_by_id(b, f->type);
    if (!p || !btf_is_func_proto(p)) return EPROTO;
    int count = btf_vlen(p), checked = s->argc;
    if (!strcmp(s->name, "udp_recvmsg")) rx_argc = count;
    fprintf(stderr, "BTF function %s id=%d argc=%d\n", s->name, id, count);
    if (checked < 0) {
        if (count != 4 && count != 5) return EPROTO;
        checked = 4;
    } else if (count != checked) return EPROTO;
    if (!matches(b, p->type, s->ret)) return EPROTO;
    const struct btf_param *params = btf_params(p);
    for (int i = 0; i < checked; i++)
        if (!matches(b, params[i].type, s->args[i])) return EPROTO;
    return 0;
}
static int check_ftrace(const struct site *sites, size_t count)
{
    FILE *file = fopen("/sys/kernel/tracing/available_filter_functions", "r");
    if (!file) return errno;
    bool found[8] = {};
    char line[512], name[256];
    unsigned int lines = 0;
    while (lines++ < 200000 && fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%255s", name) != 1) continue;
        for (size_t i = 0; i < count; i++) if (!strcmp(name, sites[i].name)) found[i] = true;
    }
    int err = ferror(file) ? EIO : 0;
    fclose(file);
    for (size_t i = 0; i < count; i++) if (!found[i]) {
        fprintf(stderr, "not available as exact ftrace function: %s (scan limit 200000 lines)\n", sites[i].name);
        return ENOENT;
    }
    return err;
}
static int check_format(const char *path, const char **fields, const int *offsets, int count)
{
    FILE *file = fopen(path, "r");
    if (!file) return errno;
    char line[512];
    unsigned int seen = 0;
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; i < count; i++) {
            char *position = strstr(line, "offset:");
            int offset = -1, size = -1;
            if (!strstr(line, fields[i]) || !position) continue;
            if (sscanf(position, "offset:%d; size:%d;", &offset, &size) != 2 ||
                offset != offsets[i] || size != (i == 0 ? 4 : 8)) { fclose(file); return EPROTO; }
            seen |= 1U << i;
        }
    }
    fclose(file);
    return seen == ((1U << count) - 1) ? 0 : EPROTO;
}
static int check_recvmsg_abi(void)
{
    const char *entry[] = {"__syscall_nr;", " fd;", " msg;", " flags;"};
    const int input_offsets[] = {8, 16, 24, 32};
    const char *leave[] = {"__syscall_nr;", " ret;"};
    const int output_offsets[] = {8, 16};
    int err = check_format("/sys/kernel/tracing/events/syscalls/sys_enter_recvmsg/format",
                           entry, input_offsets, 4);
    if (err) return err;
    err = check_format("/sys/kernel/tracing/events/syscalls/sys_exit_recvmsg/format", leave, output_offsets, 2);
    if (err) return err;
    const char *batch[] = {"__syscall_nr;", " fd;", " mmsg;", " vlen;", " flags;", " timeout;"};
    const int batch_offsets[] = {8, 16, 24, 32, 40, 48};
    err = check_format("/sys/kernel/tracing/events/syscalls/sys_enter_recvmmsg/format", batch, batch_offsets, 6);
    if (err) return err;
    return check_format("/sys/kernel/tracing/events/syscalls/sys_exit_recvmmsg/format", leave, output_offsets, 2);
}
static unsigned int pending_count(int fd, unsigned int *failures)
{
    __u64 key, next;
    unsigned int n = 0;
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && n < 256) {
        n++; key = next;
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    if (result && errno != ENOENT) (*failures)++;
    return n;
}
static unsigned int pending_selection(int fd, unsigned int *failures)
{
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1 || cpus > 4096) { (*failures)++; return 0; }
    struct selection *states = calloc((size_t)cpus, sizeof(*states));
    if (!states) { (*failures)++; return 0; }
    __u32 zero = 0;
    unsigned int active = 0;
    if (bpf_map_lookup_elem(fd, &zero, states)) (*failures)++;
    else for (int i = 0; i < cpus; i++) if (states[i].active) active++;
    free(states);
    return active;
}
static int event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct identity_event)) return -EPROTO;
    if (lifecycle_rows++ >= 4096) { lifecycle_omitted++; return 0; }
    const struct identity_event *e = data;
    printf("{\"phase\":\"lifecycle\",\"cookie\":%llu,\"at_ns\":%llu,"
           "\"cgroup\":%llu,\"pid\":%u,\"tid\":%u,\"process_start_ns\":%llu,"
           "\"thread_start_ns\":%llu,\"kind\":%u,\"netns\":%u,\"family\":%u,"
           "\"local_ipv4\":%u,\"local_port\":%u,\"peer_ipv4\":%u,\"peer_port\":%u,"
           "\"so_rcvbuf\":%u,\"so_sndbuf\":%u,\"drops\":%u,\"result\":%d,"
           "\"peer_cookie\":%llu,\"instruction_digest_fnv1a64\":%llu,\"attachment_generation\":%llu,"
           "\"program_type\":%u,\"instruction_count\":%u,\"digest_valid\":%u}\n",
           (unsigned long long)e->cookie, (unsigned long long)e->at_ns,
           (unsigned long long)e->cgroup, (unsigned int)(e->pid_tgid >> 32), (unsigned int)e->pid_tgid,
           (unsigned long long)e->process_start_ns, (unsigned long long)e->thread_start_ns,
           e->kind, e->netns, e->local.family, e->local.address, e->local.port,
           e->peer.address, e->peer.port, e->rcvbuf, e->sndbuf, e->drops, e->result,
           (unsigned long long)e->peer_cookie, (unsigned long long)e->instruction_digest,
           (unsigned long long)e->attachment_generation, e->program_type, e->instruction_count, e->digest_valid);
    return 0;
}
static int emit_witnesses(struct bpf_object *obj)
{
    int fd = bpf_object__find_map_fd_by_name(obj, "witnesses");
    __u64 key, next;
    unsigned int rows = 0;
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && rows++ < 4096) {
        key = next;
        struct witness w;
        if (bpf_map_lookup_elem(fd, &key, &w)) return 1;
        printf("{\"phase\":\"witness\",\"at_ns\":%llu,\"cookie\":%llu,"
               "\"kind\":%u,\"length\":%u,\"segment\":%u,\"result\":%lld,"
               "\"pid\":%u,\"tid\":%u,\"process_start_ns\":%llu,\"thread_start_ns\":%llu}\n",
               (unsigned long long)w.at_ns, (unsigned long long)w.key.cookie,
               w.key.kind, w.key.length, w.key.segment, (long long)w.key.result,
               (unsigned int)(w.pid_tgid >> 32), (unsigned int)w.pid_tgid,
               (unsigned long long)w.process_start_ns, (unsigned long long)w.thread_start_ns);
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    return result && errno != ENOENT;
}
static int snapshot(struct bpf_object *obj, const char *phase, unsigned long long start)
{
    int fd = bpf_object__find_map_fd_by_name(obj, "counts");
    int lfd = bpf_object__find_map_fd_by_name(obj, "losses");
    struct key key, next;
    struct value v;
    __u64 losses[LOSS_MAX] = {};
    unsigned int failures = 0, rows = 0;
    for (__u32 i = 0; i < LOSS_MAX; i++)
        if (bpf_map_lookup_elem(lfd, &i, &losses[i])) failures++;
    unsigned int tx = pending_count(bpf_object__find_map_fd_by_name(obj, "tx_pending"), &failures);
    unsigned int rx = pending_count(bpf_object__find_map_fd_by_name(obj, "rx_pending"), &failures);
    unsigned int detached = pending_count(bpf_object__find_map_fd_by_name(obj, "detach_pending"), &failures);
    unsigned int selector = pending_selection(bpf_object__find_map_fd_by_name(obj, "selection"), &failures);
    printf("{\"phase\":\"%s\",\"start_ns\":%llu,\"end_ns\":%llu,\"rows\":[",
           phase, start, now_ns());
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && rows < 4096) {
        key = next;
        if (bpf_map_lookup_elem(fd, &key, &v)) { failures++; break; }
        if (rows++) printf(",");
        printf("{\"cookie\":%llu,\"peer_cookie\":%llu,\"kind\":%u,"
               "\"length\":%u,\"segment\":%u,\"result\":%lld,\"cpu\":%u,"
               "\"count\":%llu,\"first_ns\":%llu,\"last_ns\":%llu}",
               (unsigned long long)key.cookie, (unsigned long long)key.peer, key.kind,
               key.length, key.segment, (long long)key.result, key.cpu,
               (unsigned long long)v.count, (unsigned long long)v.first_ns,
               (unsigned long long)v.last_ns);
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    if (result && errno != ENOENT) failures++;
    printf("],\"losses\":[");
    for (int i = 0; i < LOSS_MAX; i++) printf("%s%llu", i ? "," : "", (unsigned long long)losses[i]);
    printf("],\"map_read_failures\":%u,\"pending_tx\":%u,\"pending_rx\":%u,"
           "\"pending_selector\":%u,\"verifier_log_truncated\":%s,\"stream_sequence_gaps\":null,"
           "\"ring_drops\":%llu,\"pending_detach\":%u,"
           "\"stream_reason\":\"count_maps_and_bounded_unsequenced_lifecycle_ring\"}\n", failures, tx, rx, selector,
           log_truncated ? "true" : "false", (unsigned long long)losses[RING_FULL], detached);
    fflush(stdout);
    return failures ? 1 : 0;
}
#include "h1_loader.h"
int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "usage: observer OBJECT {tx|rx|classic|attach|lifetime|destroy|group|process|h1} NETNS {8192|4096|512|1} {normal|missing-btf|missing-symbol} [OWNED_CGROUP]\n");
        return 2;
    }
    const struct site *sites;
    size_t nsites;
    char prefix;
    if (!strcmp(argv[2], "h1")) { sites = h1_sites; nsites = 2; prefix = 'h'; }
    else if (!strcmp(argv[2], "tx")) { sites = tx_sites; nsites = 2; prefix = 't'; }
    else if (!strcmp(argv[2], "rx")) { sites = rx_sites; nsites = 1; prefix = 'r'; }
    else if (!strcmp(argv[2], "classic")) { sites = classic_sites; nsites = 4; prefix = 'c'; }
    else if (!strcmp(argv[2], "attach")) { sites = attach_sites; nsites = 1; prefix = 'a'; }
    else if (!strcmp(argv[2], "lifetime")) { sites = lifetime_sites; nsites = 2; prefix = 'l'; }
    else if (!strcmp(argv[2], "destroy")) { sites = destroy_sites; nsites = 3; prefix = 'd'; }
    else if (!strcmp(argv[2], "group")) { sites = group_sites; nsites = 4; prefix = 'g'; }
    else if (!strcmp(argv[2], "process")) { sites = NULL; nsites = 0; prefix = 'p'; }
    else return 2;
    h1_mode = prefix == 'h';
    live = argc == 7;
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM)) return unavailable("error", "parent_death_signal", errno);
    signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal);
    if (getppid() != parent) stopping = 1;
    if (strcmp(argv[4], "512") && strcmp(argv[4], "1") && strcmp(argv[4], "4096") &&
        !(prefix == 'h' && !strcmp(argv[4], "8192"))) return 2;
    if (prefix == 'h') {
        struct utsname host;
        if (live || uname(&host) || strcmp(host.machine, "x86_64"))
            return unavailable("unsupported", "native_amd64_required", EINVAL);
    }
    if (strcmp(argv[5], "normal") && strcmp(argv[5], "missing-btf") && strcmp(argv[5], "missing-symbol")) return 2;
    libbpf_set_print(logger);
    const char *btf_path = !strcmp(argv[5], "missing-btf") ? "/nonexistent/h3-proof-btf" : "/sys/kernel/btf/vmlinux";
    struct btf *btf = btf__parse(btf_path, NULL);
    long berr = libbpf_get_error(btf);
    if (!btf || berr) return unavailable("unsupported", "btf_read", berr ? (int)-berr : errno);
    for (size_t i = 0; i < nsites; i++) {
        int err = check_site(btf, &sites[i]);
        if (err) {
            btf__free(btf);
            return unavailable("unsupported", !strcmp(sites[i].name, "run_bpf_filter") && err == ENOENT
                ? "missing_run_bpf_filter_execution_site" : "btf_symbol_or_prototype", err);
        }
    }
    if (!strcmp(argv[5], "missing-symbol")) {
        struct site absent = {"h3_proof_deliberately_absent", 0, {NULL}, "4"};
        int err = check_site(btf, &absent);
        btf__free(btf);
        return unavailable(err ? "unsupported" : "error", "injected_missing_symbol", err);
    }
    btf__free(btf);
    int surface_error = nsites ? check_ftrace(sites, nsites) : 0;
    if (surface_error) return unavailable("unsupported", "ftrace_function_visibility", surface_error);
    if (prefix == 'r' && (surface_error = check_recvmsg_abi()))
        return unavailable("unsupported", "native_recvmsg_tracepoint_abi", surface_error);
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = verifier,
                .kernel_log_size = sizeof(verifier), .kernel_log_level = 1);
    struct bpf_object *obj = bpf_object__open_file(argv[1], &opts);
    if (!obj || libbpf_get_error(obj)) return unavailable("error", "object_open", errno);
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        bool enabled = (name[0] == prefix && name[1] == '_') || (prefix == 'c' && !strcmp(name, "a_attach"));
        if ((!strcmp(name, "r_inner4") && rx_argc != 4) ||
            (!strcmp(name, "r_inner5") && rx_argc != 5)) enabled = false;
        bpf_program__set_autoload(prog, enabled);
        if (enabled && !strcmp(name, "a_attach")) {
            // Level 1 rewinds successful paths but retains their log high-water
            // mark. That can return ENOSPC with only final statistics visible.
            // Keep the complete probe and fixed buffer; request errors + stats
            // for this program in both the attach and classic families.
            int error = bpf_program__set_log_level(prog, ATTACH_LOG_STATS);
            if (error) {
                bpf_object__close(obj);
                return unavailable("error", "attachment_log_config", -error);
            }
            fprintf(stderr, "verifier program=a_attach log_level=%u buffer_bytes=%zu\n",
                    ATTACH_LOG_STATS, sizeof(verifier));
        }
    }
    // H1 resources cannot change H3 memory admission or verifier behavior.
    struct bpf_map *selected_map;
    bpf_object__for_each_map(selected_map, obj) {
        const char *name = bpf_map__name(selected_map);
        bool h1_map = name[0] == 'h' && name[1] == '_';
        if (h1_map != (prefix == 'h')) bpf_map__set_autocreate(selected_map, false);
    }
    struct bpf_map *map = bpf_object__find_map_by_name(obj, prefix == 'h' ? "h_counts" : "counts");
    if (!map || bpf_map__set_max_entries(map, (__u32)atoi(argv[4]))) return unavailable("error", "map_config", errno);
    // Eight independently qualified families share a total 4 MiB ring budget.
    if (live && bpf_map__set_max_entries(bpf_object__find_map_by_name(obj, "lifecycle"), 512 * 1024))
        return unavailable("error", "ring_budget", errno);
    int err = bpf_object__load(obj);
    size_t verifier_bytes = strnlen(verifier, sizeof(verifier));
    // libbpf's high-level object API does not expose log_true_size. ENOSPC
    // therefore cannot certify complete diagnostics, even for a short string.
    // Conservatively flag incomplete evidence without changing errno/status.
    if (err == -ENOSPC || verifier_bytes == sizeof(verifier)) log_truncated = true;
    fprintf(stderr, "object_load result=%d kernel_log_retained_bytes=%zu buffer_bytes=%zu "
            "log_true_size=unavailable diagnostics_incomplete=%s\n",
            err, verifier_bytes, sizeof(verifier), log_truncated ? "true" : "false");
    // The shared buffer belongs to the last kernel load attempt, not necessarily
    // the attachment program. Retain it on success too, including stack stats.
    h1_redact(verifier, verifier_bytes);
    fwrite(verifier, 1, verifier_bytes, stderr);
    if (err) {
        bpf_object__close(obj);
        return unavailable(err == -EOPNOTSUPP ||
            (prefix == 'h' && (err == -EPERM || err == -EACCES || err == -ENOENT))
            ? "unsupported" : "error", "load", -err);
    }
    if (prefix == 'h') return h1_run(obj);
    __u32 zero = 0;
    char *end = NULL;
    struct config cfg = {.netns = strtoull(argv[3], &end, 10), .live = live, .start_ns = now_ns()};
    if (!end || *end || !cfg.netns) return unavailable("error", "netns_argument", EINVAL);
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "config"), &zero, &cfg, BPF_ANY))
        return unavailable("error", "configure", errno);
    if (live) {
        int cfd = open(argv[6], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cfd < 0 || bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "owned"), &zero, &cfd, BPF_ANY))
            return unavailable("error", "owned_cgroup", errno);
        close(cfd);
    }
    struct ring_buffer *ring = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "lifecycle"), event, NULL, NULL);
    if (!ring) return unavailable("error", "ring_create", errno);
    struct bpf_link *links[16] = {};
    int nlinks = 0;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__autoload(prog)) continue;
        fprintf(stderr, "attach %s\n", bpf_program__section_name(prog));
        struct bpf_link *link = bpf_program__attach(prog);
        err = (int)libbpf_get_error(link);
        if (!link || err) {
            if (!err) err = -errno;
            for (int i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
            bpf_object__close(obj);
            return unavailable(err == -EPERM || err == -EACCES || err == -ENOENT || err == -EOPNOTSUPP
                               ? "unsupported" : "error", "attach", -err);
        }
        links[nlinks++] = link;
    }
    signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal);
    unsigned long long start = now_ns();
    printf("{\"phase\":\"ready\",\"status\":\"supported\",\"family\":\"%s\","
           "\"netns\":%llu,\"start_ns\":%llu,\"links\":%d,\"exercise_verified\":false}\n",
           argv[2], (unsigned long long)cfg.netns, start, nlinks);
    fflush(stdout);
    // One session through retirement; fixed hard cap, explicit parent/timeout outcome.
    int status = 0, snapshots = 0, checkpoints_omitted = 0;
    unsigned long long checkpoint = start;
    bool requested_stop = false;
    while (!stopping && now_ns() - start < (live ? 300000000000ULL : 30000000000ULL)) {
        int consumed = ring_buffer__consume(ring);
        if (consumed < 0) { status = 1; break; }
        if (live && now_ns() - checkpoint >= 10000000000ULL && snapshots < 63) {
            status |= snapshot(obj, "checkpoint", start); snapshots++; checkpoint = now_ns();
        }
        struct pollfd p = {.fd = STDIN_FILENO, .events = POLLIN};
        if (poll(&p, 1, 100) <= 0) continue;
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        if (c == 'q') { requested_stop = true; break; }
        if (c == 's') {
            if (snapshots < (live ? 63 : 4)) { snapshots++; status |= snapshot(obj, "snapshot", start); }
            else checkpoints_omitted++;
        }
    }
    // Detach before final reads: final map iteration has no concurrent writers.
    for (int i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
    if (ring_buffer__consume(ring) < 0) status = 1;
    if (live) status |= emit_witnesses(obj);
    status |= snapshot(obj, "final", start);
    printf("{\"phase\":\"termination\",\"requested_stop\":%s,\"signal\":%s,"
           "\"forced_or_parent_death\":%s,\"lifecycle_omitted\":%u,\"snapshot_failures\":%d,\"checkpoints_omitted\":%d}\n",
           requested_stop ? "true" : "false", stopping ? "true" : "false",
           requested_stop ? "false" : "true", lifecycle_omitted, status, checkpoints_omitted);
    ring_buffer__free(ring);
    bpf_object__close(obj);
    return status;
}
