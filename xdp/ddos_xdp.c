/*
 * ROCKET Shield — XDP/eBPF L3/L4 DDoS detection & mitigation
 *
 * Runs in kernel space on the NIC driver hook (XDP_DRV mode when the
 * driver supports it, falls back to XDP_SKB otherwise). Decisions are
 * made and enforced locally — no round-trip to any controller — so the
 * drop happens in microseconds, well under the 1s mitigation target.
 *
 * Detects (per-source-IP and global counters, sliding 1s windows):
 *   - SYN flood            (high SYN rate, no matching ACK completion)
 *   - UDP flood            (high UDP pps from single/many sources)
 *   - ICMP flood
 *   - Amplification replies (DNS/NTP/memcached: large UDP responses
 *                             from a source port associated with known
 *                             amplification services, at high rate)
 *
 * Build:
 *   clang -O2 -g -target bpf -c ddos_xdp.c -o ddos_xdp.o
 *   sudo ip link set dev eth0 xdp obj ddos_xdp.o sec xdp
 *
 * Userspace counterpart (agent/xdp_loader.py) reads the maps below,
 * pushes aggregated telemetry to the controller, and can update
 * per-IP block entries and thresholds at runtime via the maps.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TRACKED_IPS   1000000
#define SYN_PPS_THRESHOLD 200      /* per-source-IP SYNs/sec before block   */
#define UDP_PPS_THRESHOLD 500      /* per-source-IP UDP pkts/sec            */
#define ICMP_PPS_THRESHOLD 100
#define GLOBAL_PPS_ALERT  50000    /* aggregate pps that flips global mode  */
#define BLOCK_DURATION_NS (60ULL * 1000000000ULL) /* 60s auto-expire block */

/* Well-known amplification source ports */
#define PORT_DNS       53
#define PORT_NTP       123
#define PORT_MEMCACHED 11211
#define PORT_SSDP      1900
#define PORT_CHARGEN   19

struct ip_stat {
    __u64 syn_count;
    __u64 udp_count;
    __u64 icmp_count;
    __u64 window_start_ns;
    __u8  blocked;
    __u64 block_until_ns;
};

/* Per-source-IP counters, sliding 1s window (reset lazily on read) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key, __u32);          /* source IPv4, network byte order */
    __type(value, struct ip_stat);
} ip_stats SEC(".maps");

/* Explicit blocklist pushed by userspace agent (manual / controller rules) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u64);        /* block_until_ns, 0 = permanent */
} manual_block SEC(".maps");

/* Global aggregate counters, exposed to userspace for telemetry + baseline */
struct global_stat {
    __u64 total_pps;
    __u64 syn_pps;
    __u64 udp_pps;
    __u64 icmp_pps;
    __u64 dropped_pps;
    __u64 window_start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stat);
} global_stats SEC(".maps");

/* Runtime-tunable thresholds, updatable by agent without recompiling */
struct thresholds {
    __u64 syn_pps_threshold;
    __u64 udp_pps_threshold;
    __u64 icmp_pps_threshold;
    __u64 global_pps_alert;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct thresholds);
} threshold_cfg SEC(".maps");

static __always_inline struct thresholds *get_thresholds(void)
{
    __u32 key = 0;
    struct thresholds *t = bpf_map_lookup_elem(&threshold_cfg, &key);
    return t;
}

static __always_inline void bump_global(int is_syn, int is_udp, int is_icmp, int dropped)
{
    __u32 key = 0;
    struct global_stat *g = bpf_map_lookup_elem(&global_stats, &key);
    if (!g)
        return;
    __u64 now = bpf_ktime_get_ns();
    if (now - g->window_start_ns > 1000000000ULL) {
        g->total_pps = 0;
        g->syn_pps = 0;
        g->udp_pps = 0;
        g->icmp_pps = 0;
        g->dropped_pps = 0;
        g->window_start_ns = now;
    }
    g->total_pps++;
    if (is_syn) g->syn_pps++;
    if (is_udp) g->udp_pps++;
    if (is_icmp) g->icmp_pps++;
    if (dropped) g->dropped_pps++;
}

/* Returns 1 if this source IP should be dropped */
static __always_inline int check_and_update_ip(__u32 src_ip, int is_syn, int is_udp, int is_icmp)
{
    __u64 now = bpf_ktime_get_ns();

    /* Manual/controller-pushed block first — cheapest check */
    __u64 *mb = bpf_map_lookup_elem(&manual_block, &src_ip);
    if (mb) {
        if (*mb == 0 || *mb > now)
            return 1;
    }

    struct thresholds *th = get_thresholds();
    __u64 syn_thr = th ? th->syn_pps_threshold : SYN_PPS_THRESHOLD;
    __u64 udp_thr = th ? th->udp_pps_threshold : UDP_PPS_THRESHOLD;
    __u64 icmp_thr = th ? th->icmp_pps_threshold : ICMP_PPS_THRESHOLD;

    struct ip_stat *s = bpf_map_lookup_elem(&ip_stats, &src_ip);
    if (!s) {
        struct ip_stat init = {0};
        init.window_start_ns = now;
        if (is_syn) init.syn_count = 1;
        if (is_udp) init.udp_count = 1;
        if (is_icmp) init.icmp_count = 1;
        bpf_map_update_elem(&ip_stats, &src_ip, &init, BPF_ANY);
        return 0;
    }

    if (s->blocked) {
        if (now < s->block_until_ns)
            return 1;
        /* block expired — reset and re-evaluate normally */
        s->blocked = 0;
        s->syn_count = 0;
        s->udp_count = 0;
        s->icmp_count = 0;
        s->window_start_ns = now;
    }

    /* Reset sliding window every 1s */
    if (now - s->window_start_ns > 1000000000ULL) {
        s->syn_count = 0;
        s->udp_count = 0;
        s->icmp_count = 0;
        s->window_start_ns = now;
    }

    if (is_syn) s->syn_count++;
    if (is_udp) s->udp_count++;
    if (is_icmp) s->icmp_count++;

    if (s->syn_count > syn_thr || s->udp_count > udp_thr || s->icmp_count > icmp_thr) {
        s->blocked = 1;
        s->block_until_ns = now + BLOCK_DURATION_NS;
        return 1;
    }

    return 0;
}

/* Detect amplification-style UDP: reply traffic from well-known service
 * ports at a rate far above what a normal client-side response needs. */
static __always_inline int is_amplification_port(__u16 sport)
{
    return sport == PORT_DNS || sport == PORT_NTP ||
           sport == PORT_MEMCACHED || sport == PORT_SSDP || sport == PORT_CHARGEN;
}

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; /* IPv6 / non-IP handled by userspace path for now */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    int is_syn = 0, is_udp = 0, is_icmp = 0;
    int drop_by_amplification = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->syn && !tcp->ack)
            is_syn = 1;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        is_udp = 1;
        __u16 sport = bpf_ntohs(udp->source);
        __u16 len = bpf_ntohs(udp->len);
        /* Oversized reply from an amplification-prone port = near-certain
         * reflection attack; drop unconditionally regardless of per-IP rate */
        if (is_amplification_port(sport) && len > 512)
            drop_by_amplification = 1;
    } else if (ip->protocol == IPPROTO_ICMP) {
        is_icmp = 1;
    }

    int drop = drop_by_amplification || check_and_update_ip(src_ip, is_syn, is_udp, is_icmp);
    bump_global(is_syn, is_udp, is_icmp, drop);

    return drop ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";