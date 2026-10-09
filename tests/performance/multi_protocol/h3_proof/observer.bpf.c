// SPDX-License-Identifier: GPL-2.0
// No payload, packet header, program instruction or kernel pointer export.
// Only allowlisted IPv4 endpoint and socket/process metadata leaves the observer.
#include <linux/bpf.h>
#include "core_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "contract.h"
#include "rx_contract.h"
#include "socket_contract.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct config);
} config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, struct key); __type(value, struct value);
} counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, LOSS_MAX);
    __type(key, __u32); __type(value, __u64);
} losses SEC(".maps");

static __always_inline void loss(__u32 n)
{
    __u64 *v = bpf_map_lookup_elem(&losses, &n);
    if (v) __sync_fetch_and_add(v, 1);
}

// One owned subtree, supplied before child creation. No gateway gets map access.
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32);
} owned SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, __u64); __type(value, struct identity_event);
} sockets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 4 * 1024 * 1024);
} lifecycle SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u64); __type(value, struct witness);
} witnesses SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 32);
    __type(key, __u32); __type(value, __u64);
} sequence SEC(".maps");

static __always_inline int local_task(void)
{
    __u32 zero = 0, ns = 0;
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    struct task_struct *task = (void *)bpf_get_current_task();
    if (!c) return 0;
    if (c->live) return bpf_current_task_under_cgroup(&owned, 0) == 1;
    if (BPF_CORE_READ_INTO(&ns, task, nsproxy, net_ns, ns.inum)) {
        loss(READ_FAILED); return 0;
    }
    return ns == c->netns;
}

static __always_inline __u64 identity(struct sock *sk)
{
    __u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    if (!sk || !c) return 0;
    if (BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != c->netns) return 0;
    // The helper takes PTR_TO_BTF_ID, never a pointer reconstructed by probe-read.
    // Direct CO-RE field access preserves that type through tracing contexts.
    if (c->live && !local_task()) {
        __u64 prior = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
        return prior && bpf_map_lookup_elem(&sockets, &prior) ? prior : 0;
    }
    __u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie) loss(UNKNOWN_COOKIE);
    return cookie;
}

static __noinline void socket_event(struct sock *sk, __u64 cookie, __u32 kind,
                                         int result, struct msghdr *msg)
{
    __u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    if (!cookie || !c || !c->live) return;
    if (!local_task() && kind != SOCKET_RETIRE) return;
    struct identity_event e = {.cookie = cookie, .kind = kind, .result = result,
        .at_ns = bpf_ktime_get_ns(), .cgroup = bpf_get_current_cgroup_id(),
        .pid_tgid = bpf_get_current_pid_tgid(), .netns = c->netns};
    struct task_struct *task = (void *)bpf_get_current_task();
    e.thread_start_ns = BPF_CORE_READ(task, start_boottime);
    e.process_start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    e.local.address = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e.local.port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e.local.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e.peer.family = e.local.family;
    e.peer.address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e.peer.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e.rcvbuf = BPF_CORE_READ(sk, sk_rcvbuf); e.sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
    e.drops = BPF_CORE_READ(sk, sk_drops.counter);
    // Only the allowlisted IPv4 destination endpoint; never packet/CID data.
    if (msg && BPF_CORE_READ(msg, msg_namelen) >= 16) { // IPv4 sockaddr ABI size
        struct sockaddr_in *addr = BPF_CORE_READ(msg, msg_name);
        __u16 family = 0, port = 0;
        __u32 address = 0;
        // Relocate kernel field accesses, never offsets into a partial stack copy.
        if (BPF_CORE_READ_INTO(&family, addr, sin_family) ||
            BPF_CORE_READ_INTO(&address, addr, sin_addr.s_addr) ||
            BPF_CORE_READ_INTO(&port, addr, sin_port))
            loss(READ_FAILED);
        else if (family == 2) {
            e.peer.address = address; e.peer.port = bpf_ntohs(port);
        }
    }
    struct identity_event *previous = bpf_map_lookup_elem(&sockets, &cookie);
    if (kind == SOCKET_RETIRE && previous) {
        e.pid_tgid = previous->pid_tgid; e.cgroup = previous->cgroup;
        e.process_start_ns = previous->process_start_ns; e.thread_start_ns = previous->thread_start_ns;
    }
    if (!e.peer.port && previous) e.peer = previous->peer;
    // Shared by TX, RX and retirement enrollment. Both fixed listeners must
    // suppress peer churn before the ring, leaving bounded space for teardown.
    // Owner, local tuple and buffer changes still emit; retirement always emits.
    if (h3_same_socket_observation(&e, previous)) return;
    if (bpf_map_update_elem(&sockets, &cookie, &e, BPF_ANY)) loss(IDENTITY_FULL);
    if (bpf_ringbuf_output(&lifecycle, &e, sizeof(e), 0)) loss(RING_FULL);
}

static __noinline void record(struct key *key)
{
    struct value *v, initial = {};
    __u32 zero = 0;
    __u64 now = bpf_ktime_get_ns();
    struct config *c = bpf_map_lookup_elem(&config, &zero);
    key->cpu = bpf_get_smp_processor_id(); // CPU is not a worker identity.
    loss(ATTEMPTS);
    if (c && c->live) {
        __u32 window = (now - c->start_ns) / 10000000000ULL;
        if (window > 31) window = 31;
        __u64 *seq = bpf_map_lookup_elem(&sequence, &window);
        if (seq) {
            __u64 n = __sync_fetch_and_add(seq, 1);
            if (n < 128) {
                n += window * 128;
                struct task_struct *task = (void *)bpf_get_current_task();
                struct witness w = {.key = *key, .at_ns = now,
                    .pid_tgid = bpf_get_current_pid_tgid(),
                    .process_start_ns = BPF_CORE_READ(task, group_leader, start_boottime),
                    .thread_start_ns = BPF_CORE_READ(task, start_boottime)};
                if (bpf_map_update_elem(&witnesses, &n, &w, BPF_NOEXIST)) loss(MAP_FULL);
            } else loss(WITNESS_FULL);
        }
        // Fixed buckets per cookie/outcome. Exact values only in bounded witnesses.
        __u32 segments = key->segment ? (key->length + key->segment - 1) / key->segment : 0;
        key->segment = segments > 16 ? 5 : segments > 8 ? 4 : segments > 4 ? 3 : segments > 1 ? 2 : segments;
        key->length = 0; key->result = key->result < 0 ? -1 : 0; key->cpu = 0;
    }
    v = bpf_map_lookup_elem(&counts, key);
    if (!v) {
        initial.first_ns = now;
        bpf_map_update_elem(&counts, key, &initial, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&counts, key);
    }
    if (!v) { loss(MAP_FULL); return; }
    __sync_fetch_and_add(&v->count, 1); v->last_ns = now; loss(RECORDED);
}

struct tx { __u64 cookie; __u32 length, segment, seen, flags, depth; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct tx);
} tx_pending SEC(".maps");

SEC("fentry/udp_sendmsg") int BPF_PROG(t_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx t = {.cookie = identity(sk), .length = len};
    if (!t.cookie) return 0;
    socket_event(sk, t.cookie, SOCKET_OBSERVED, 0, msg);
    if (BPF_CORE_READ_INTO(&t.flags, msg, msg_flags)) {
        loss(READ_FAILED); return 0;
    }
    struct tx *previous = bpf_map_lookup_elem(&tx_pending, &tid);
    if (previous) { loss(NESTED); previous->depth++; previous->flags |= 0x8000; return 0; }
    if (bpf_map_update_elem(&tx_pending, &tid, &t, BPF_NOEXIST)) loss(MAP_FULL);
    return 0;
}

// The effective segment size after socket defaults and u16 UDP_SEGMENT cmsg
// validation, in the actual IPv4 submission path. Missing/inlined site => unsupported.
SEC("fentry/udp_send_skb") int BPF_PROG(t_effective, struct sk_buff *skb, void *fl4, struct inet_cork *cork)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx *t = bpf_map_lookup_elem(&tx_pending, &tid);
    struct sock *sk = skb->sk;
    __u16 segment = 0;
    if (!t) return 0;
    if (BPF_CORE_READ_INTO(&segment, cork, gso_size)) {
        loss(READ_FAILED); return 0;
    }
    if (identity(sk) != t->cookie) { loss(UNMATCHED); return 0; }
    t->segment = segment;
    t->seen++;
    return 0;
}

SEC("fexit/udp_sendmsg") int t_exit(__u64 *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct tx *t = bpf_map_lookup_elem(&tx_pending, &tid);
    if (!t) return 0;
    if (t->depth) { t->depth--; return 0; }
    struct key k = {.cookie = t->cookie, .length = t->length,
                    .segment = t->segment, .result = (int)ctx[3]};
    if (k.result < 0) k.kind = TX_ERROR;
    else if (k.result != t->length || t->seen != 1 || (t->flags & 0x8000))
        k.kind = TX_UNCOVERED; // partial result, cork/MSG_MORE, nested submission
    else k.kind = t->segment && t->length > t->segment ? TX_GSO : TX_ORDINARY;
    record(&k);
    bpf_map_delete_elem(&tx_pending, &tid);
    return 0;
}

SEC("tp/sched/sched_process_exit") int t_death(void *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&tx_pending, &tid)) {
        loss(ABANDONED); bpf_map_delete_elem(&tx_pending, &tid);
    }
    return 0;
}

// Native Linux amd64 only. Loader checks sizeof(struct msghdr) and target arch.
// Read only ABI metadata and the allowlisted native-int UDP_GRO value.
struct enter { __u64 common; int id; __u32 pad; __u64 args[6]; };
struct leave { __u64 common; int id; __u32 pad; long ret; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct rx);
} rx_pending SEC(".maps");
// Zero template in a map: a 32-slot receive vector must never live on BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct rx);
} rx_zero SEC(".maps");

static __always_inline int receive_enter(struct enter *ctx, int batch)
{
    if (!local_task()) return 0;
    // native x86_64 recvmsg=47, recvmmsg=299; x32/compat are never decoded.
    if (ctx->id != (batch ? 299 : 47)) { loss(EXCLUDED_API); return 0; }
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 zero = 0, vlen = batch ? ctx->args[2] : 1;
    struct rx *old = bpf_map_lookup_elem(&rx_pending, &tid);
    if (old) { old->invalid = 1; loss(NESTED); return 0; }
    if (!h3_native_call(ctx->id, batch, vlen)) { loss(EXCLUDED_API); return 0; }
    struct rx *empty = bpf_map_lookup_elem(&rx_zero, &zero);
    if (!empty || bpf_map_update_elem(&rx_pending, &tid, empty, BPF_NOEXIST)) {
        loss(MAP_FULL); return 0;
    }
    struct rx *r = bpf_map_lookup_elem(&rx_pending, &tid);
    if (!r) return 0;
    r->generation = bpf_ktime_get_ns(); r->vlen = vlen; r->batch = batch;
    r->hdr = ctx->args[1]; r->flags = ctx->args[batch ? 3 : 2];
    for (__u32 i = 0; i < 32; i++) {
        if (i >= vlen) break;
        struct user_msg h = {};
        struct rx_slot *slot = &r->slots[i];
        slot->hdr = r->hdr + (batch ? i * 64 : 0);
        if (bpf_probe_read_user(&h, sizeof(h), (void *)slot->hdr)) {
            loss(READ_FAILED); continue; // A bad trailing slot must not erase a good prefix.
        }
        slot->control = h.control; slot->capacity = h.controllen; slot->readable = 1;
    }
    return 0;
}
SEC("tp/syscalls/sys_enter_recvmsg") int r_enter(struct enter *ctx) { return receive_enter(ctx, 0); }
SEC("tp/syscalls/sys_enter_recvmmsg") int r_m_enter(struct enter *ctx) { return receive_enter(ctx, 1); }

SEC("fentry/udp_recvmsg") int BPF_PROG(r_socket, struct sock *sk)
{
    __u64 cookie = identity(sk), tid = bpf_get_current_pid_tgid();
    if (!cookie) return 0;
    socket_event(sk, cookie, SOCKET_OBSERVED, 0, 0);
    struct rx *r = bpf_map_lookup_elem(&rx_pending, &tid);
    if (!r) { loss(EXCLUDED_API); return 0; }
    if ((r->cookie && r->cookie != cookie) || r->active) { r->invalid = 1; loss(UNMATCHED); }
    r->cookie = cookie; r->entries++; r->active = 1;
    return 0;
}
// Loader selects the verified four- or five-argument prototype's return slot.
static __always_inline int inner_exit(long ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct rx *r = bpf_map_lookup_elem(&rx_pending, &tid);
    if (r) { r->active = 0; if (ret < 0) { r->inner_errors++; loss(INNER_ERROR); } }
    return 0;
}
SEC("fexit/udp_recvmsg") int r_inner4(__u64 *ctx) { return inner_exit((int)ctx[4]); }
SEC("fexit/udp_recvmsg") int r_inner5(__u64 *ctx) { return inner_exit((int)ctx[5]); }

static __noinline void decode(struct rx_slot *slot, __u64 cookie, __u32 flags, long bytes)
{
    __u64 offset = 0;
    struct user_msg h = {};
    struct key k = {.cookie = cookie, .result = bytes, .length = bytes};
    if (!slot->readable) return;
    if (flags & 8192) { loss(EXCLUDED_API); return; } // MSG_ERRQUEUE
    if (bpf_probe_read_user(&h, sizeof(h), (void *)slot->hdr)) goto unreadable;
    if (!h3_control_bounds(slot->control, slot->capacity, h.control, h.controllen))
        goto unreadable;
    if (h.flags & (8 | 32)) { k.kind = RX_TRUNCATED; goto emit; }
    if (flags & 2) { k.kind = RX_PEEK; goto emit; }
    k.kind = bytes ? RX_ORDINARY : RX_ZERO;
    for (int i = 0; i < 8; i++) {
        struct user_cmsg c = {};
        int segment = 0;
        if (offset == h.controllen) break;
        if (offset + sizeof(c) > h.controllen || h.control + offset < h.control) goto unreadable;
        if (bpf_probe_read_user(&c, sizeof(c), (void *)(h.control + offset))) goto unreadable;
        if (!h3_cmsg_shape(&c, h.controllen - offset, k.segment)) goto unreadable;
        if (c.level == 17 && c.type == 104) {
            if (bpf_probe_read_user(&segment, sizeof(segment),
                                    (void *)(h.control + offset + sizeof(c)))) goto unreadable;
            if (!h3_segment_valid(segment)) goto unreadable;
            k.segment = segment;
        }
        offset += (c.length + 7) & ~7ULL;
        if (offset > h.controllen && offset - h.controllen < 8) offset = h.controllen;
    }
    if (offset != h.controllen) goto unreadable;
    if (h3_delivered_gro(k.length, k.segment, h.flags, flags)) k.kind = RX_GRO;
emit:
    record(&k); return;
unreadable:
    loss(READ_FAILED);
}

static __always_inline int receive_exit(struct leave *ctx, int batch)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct rx *r = bpf_map_lookup_elem(&rx_pending, &tid);
    if (!r) return 0;
    if (r->batch != batch || ctx->id != (batch ? 299 : 47) || r->invalid || r->active) {
        loss(UNMATCHED); goto done;
    }
    if (!r->cookie) goto done;
    struct key k = {.cookie = r->cookie, .result = ctx->ret};
    if (ctx->ret < 0) { k.kind = RX_ERROR; record(&k); goto done; }
    if (!batch) { decode(&r->slots[0], r->cookie, r->flags, ctx->ret); goto done; }
    k.kind = RX_BATCH; k.length = r->vlen; k.segment = r->entries;
    record(&k); // syscall count is NEVER a per-message byte result.
    if (!ctx->ret) goto done;
    if (!h3_prefix_valid(ctx->ret, r->vlen, r->entries)) { loss(UNMATCHED); goto done; }
    if (ctx->ret < r->vlen) loss(BATCH_PARTIAL);
    for (__u32 i = 0; i < 32; i++) {
        if (i >= ctx->ret) break;
        __u32 bytes = 0;
        struct rx_slot *slot = &r->slots[i];
        if (bpf_probe_read_user(&bytes, sizeof(bytes), (void *)(slot->hdr + 56))) {
            loss(READ_FAILED); continue;
        }
        decode(slot, r->cookie, r->flags, bytes);
    }
done:
    bpf_map_delete_elem(&rx_pending, &tid); return 0;
}
SEC("tp/syscalls/sys_exit_recvmsg") int r_exit(struct leave *ctx) { return receive_exit(ctx, 0); }
SEC("tp/syscalls/sys_exit_recvmmsg") int r_m_exit(struct leave *ctx) { return receive_exit(ctx, 1); }
SEC("tp/sched/sched_process_exit") int r_death(void *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&rx_pending, &tid)) { loss(ABANDONED); bpf_map_delete_elem(&rx_pending, &tid); }
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct selection);
} selection SEC(".maps");

SEC("fentry/reuseport_select_sock") int BPF_PROG(c_enter, struct sock *sk)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    __u64 cookie = identity(sk);
    if (!s || !cookie) return 0;
    if (s->active) { loss(NESTED); s->active = 2; return 0; }
    s->anchor = cookie; s->inner = 0; s->selected = 0; s->active = 1;
    return 0;
}

SEC("fexit/run_bpf_filter") int BPF_PROG(c_filter, struct sock_reuseport *reuse, __u16 n, void *prog, struct sk_buff *skb, int offset, struct sock *selected)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    struct key k = {};
    if (!s || s->active != 1) return 0;
    // Correlate with the typed lookup socket captured at c_enter. It can be
    // any group member; a flexible-array load cannot provide a verifier-safe
    // PTR_TO_BTF_ID for bpf_get_socket_cookie on newer kernels.
    k.cookie = s->anchor;
    if (!k.cookie) return 0;
    k.peer = identity(selected);
    if (selected && !k.peer) return 0;
    k.kind = k.peer ? CLASSIC_SELECTED : CLASSIC_NULL;
    s->inner = 1; s->selected = k.peer;
    record(&k);
    return 0;
}

SEC("fexit/reuseport_select_sock") int BPF_PROG(c_exit, struct sock *sk, __u32 hash, struct sk_buff *skb, int offset, struct sock *selected)
{
    __u32 zero = 0;
    struct selection *s = bpf_map_lookup_elem(&selection, &zero);
    if (!s || !s->active) return 0;
    if (identity(sk) != s->anchor) return 0;
    if (s->active == 1 && s->inner) {
        struct key k = {.cookie = s->anchor, .peer = identity(selected),
                        .kind = s->selected ? SELECTOR_SELECTED : SELECTOR_FALLBACK};
        record(&k);
    } else loss(UNMATCHED);
    s->active = 0;
    return 0;
}

SEC("fexit/inet_bind") int BPF_PROG(c_bind, struct socket *sock, struct sockaddr *addr, int len, int ret)
{
    if (!ret && sock && sock->sk && BPF_CORE_READ(sock->sk, sk_protocol) == 17) {
        struct sock *sk = sock->sk;
        socket_event(sk, identity(sk), SOCKET_BIND, ret, 0);
    }
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, __u64); __type(value, __u64);
} attachment_generation SEC(".maps");

static __noinline void attachment_event(struct sock *sk, struct bpf_prog *prog, int ret)
{
    __u64 cookie = identity(sk);
    if (!cookie) return;
    struct identity_event e = {.cookie = cookie, .at_ns = bpf_ktime_get_ns(),
        .kind = ret ? ATTACH_ERROR : ATTACH_OK, .result = ret,
        .pid_tgid = bpf_get_current_pid_tgid(), .cgroup = bpf_get_current_cgroup_id(), .netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum)};
    if (!ret) {
        __u64 one = 1, *gen = bpf_map_lookup_elem(&attachment_generation, &cookie);
        if (gen) e.attachment_generation = __sync_add_and_fetch(gen, 1);
        else {
            e.attachment_generation = 1;
            if (bpf_map_update_elem(&attachment_generation, &cookie, &one, BPF_NOEXIST)) loss(MAP_FULL);
        }
    }
    if (prog) {
        e.program_type = BPF_CORE_READ(prog, type);
        struct sock_fprog_kern *original = BPF_CORE_READ(prog, orig_prog);
        if (original) {
            __u16 n = BPF_CORE_READ(original, len);
            struct sock_filter *filter = BPF_CORE_READ(original, filter);
            e.instruction_count = n;
            if (n && n <= 64) {
                __u64 hash = 14695981039346656037ULL;
                e.digest_valid = 1;
                for (int i = 0; i < 64; i++) {
                    if (i >= n) break;
                    __u8 bytes[8] = {};
                    if (bpf_probe_read_kernel(bytes, sizeof(bytes), &filter[i])) {
                        e.digest_valid = 0; loss(READ_FAILED); break;
                    }
                    for (int j = 0; j < 8; j++) hash = (hash ^ bytes[j]) * 1099511628211ULL;
                }
                if (e.digest_valid) e.instruction_digest = hash; // FNV-1a, not a security hash.
            }
        }
    }
    if (bpf_ringbuf_output(&lifecycle, &e, sizeof(e), 0)) loss(RING_FULL);
}

SEC("fexit/reuseport_attach_prog") int BPF_PROG(a_attach, struct sock *sk, struct bpf_prog *prog, int ret)
{
    struct key k = {.cookie = identity(sk), .result = ret};
    if (!k.cookie) return 0;
    k.kind = k.result == 0 ? ATTACH_OK : ATTACH_ERROR;
    socket_event(sk, k.cookie, k.kind, ret, 0);
    attachment_event(sk, prog, ret);
    record(&k);
    return 0;
}
// Independently loadable lifetime family. Missing birth sites never become births.
SEC("fexit/inet_create") int BPF_PROG(l_birth, struct net *net, struct socket *sock, int protocol, int kern, int ret)
{
    if (!ret && sock && sock->sk && BPF_CORE_READ(sock->sk, sk_protocol) == 17) {
        struct sock *sk = sock->sk;
        socket_event(sk, identity(sk), SOCKET_BIRTH, ret, 0);
    }
    return 0;
}
SEC("fexit/inet_bind") int BPF_PROG(l_bind, struct socket *sock, struct sockaddr *addr, int len, int ret)
{
    if (!ret && sock && sock->sk && BPF_CORE_READ(sock->sk, sk_protocol) == 17) {
        struct sock *sk = sock->sk;
        socket_event(sk, identity(sk), SOCKET_BIND, ret, 0);
    }
    return 0;
}
SEC("fentry/udp_destroy_sock") int BPF_PROG(d_retire, struct sock *sk)
{
    socket_event(sk, identity(sk), SOCKET_RETIRE, 0, 0);
    return 0;
}
// Enrollment in the retirement object's map permits deferred destruction on a
// non-workload task without claiming that softirq context is a worker identity.
SEC("fentry/udp_sendmsg") int BPF_PROG(d_enroll, struct sock *sk, struct msghdr *msg)
{
    socket_event(sk, identity(sk), SOCKET_OBSERVED, 0, msg); return 0;
}
SEC("fentry/udp_recvmsg") int BPF_PROG(d_receive, struct sock *sk)
{
    socket_event(sk, identity(sk), SOCKET_OBSERVED, 0, 0); return 0;
}

static __noinline void group_event(struct sock *sk, struct sock *peer, __u32 kind, int ret)
{
    __u64 cookie = identity(sk);
    if (!cookie) return;
    struct key k = {.cookie = cookie, .peer = peer ? identity(peer) : 0, .kind = kind, .result = ret};
    record(&k);
    struct identity_event e = {.cookie = cookie, .peer_cookie = k.peer, .kind = kind,
        .result = ret, .at_ns = bpf_ktime_get_ns(), .pid_tgid = bpf_get_current_pid_tgid(),
        .cgroup = bpf_get_current_cgroup_id(), .netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum)};
    if (bpf_ringbuf_output(&lifecycle, &e, sizeof(e), 0)) loss(RING_FULL);
}
SEC("fexit/reuseport_alloc") int BPF_PROG(g_alloc, struct sock *sk, _Bool bind_any, int ret)
{
    group_event(sk, 0, GROUP_ALLOC, ret); return 0;
}
SEC("fexit/reuseport_add_sock") int BPF_PROG(g_add, struct sock *sk, struct sock *peer, _Bool bind_any, int ret)
{
    group_event(sk, peer, GROUP_ADD, ret); return 0;
}
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, __u64);
} detach_pending SEC(".maps");
SEC("fentry/reuseport_detach_sock") int BPF_PROG(g_detach_enter, struct sock *sk)
{
    __u64 tid = bpf_get_current_pid_tgid(), cookie = identity(sk);
    if (cookie && BPF_CORE_READ(sk, sk_reuseport_cb))
        if (bpf_map_update_elem(&detach_pending, &tid, &cookie, BPF_NOEXIST)) loss(NESTED);
    return 0;
}
SEC("fexit/reuseport_detach_sock") int BPF_PROG(g_detach_exit, struct sock *sk)
{
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 *cookie = bpf_map_lookup_elem(&detach_pending, &tid);
    if (cookie && *cookie == identity(sk) && !BPF_CORE_READ(sk, sk_reuseport_cb))
        group_event(sk, 0, GROUP_DETACH, 0);
    else if (cookie) loss(UNMATCHED);
    bpf_map_delete_elem(&detach_pending, &tid); return 0;
}
SEC("fexit/reuseport_detach_prog") int BPF_PROG(g_prog_detach, struct sock *sk, int ret)
{
    group_event(sk, 0, PROGRAM_DETACH, ret); return 0;
}
SEC("tp/sched/sched_process_exit") int g_death(void *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&detach_pending, &tid)) {
        loss(ABANDONED); bpf_map_delete_elem(&detach_pending, &tid);
    }
    return 0;
}

static __always_inline void process_event(struct task_struct *task, __u32 kind)
{
    if (!local_task()) return;
    struct identity_event e = {.kind = kind, .at_ns = bpf_ktime_get_ns(),
        .cgroup = bpf_get_current_cgroup_id(),
        .pid_tgid = ((__u64)BPF_CORE_READ(task, tgid) << 32) | (__u32)BPF_CORE_READ(task, pid),
        .process_start_ns = BPF_CORE_READ(task, group_leader, start_boottime),
        .thread_start_ns = BPF_CORE_READ(task, start_boottime),
        .netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum)};
    if (bpf_ringbuf_output(&lifecycle, &e, sizeof(e), 0)) loss(RING_FULL);
}
SEC("tp_btf/sched_process_fork") int BPF_PROG(p_fork, struct task_struct *parent, struct task_struct *child)
{
    process_event(child, PROCESS_FORK); return 0;
}
SEC("tp_btf/sched_process_exec") int BPF_PROG(p_exec, struct task_struct *task)
{
    process_event(task, PROCESS_EXEC); return 0;
}
SEC("tp_btf/sched_process_exit") int BPF_PROG(p_exit, struct task_struct *task)
{
    process_event(task, PROCESS_DEATH); return 0;
}
#include "h1_syscalls.bpf.h"
char LICENSE[] SEC("license") = "GPL";
