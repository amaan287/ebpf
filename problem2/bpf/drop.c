//go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// IP protocol numbers
#define IPPROTO_TCP 6

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

// eBPF program
SEC("xdp")
int drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr*)(eth + 1);
        if ((void*)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr*)(ip + 1);
            if ((void*)(tcp + 1) > data_end)
                return XDP_PASS;

            __u32 key = 0;
            __u16 *port = bpf_map_lookup_elem(&blocked_port, &key);
            if (port && tcp->dest == __constant_htons(*port)) {
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
