//go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

 
SEC("xdp")
int drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr*)(eth + 1);
        if ((void*)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr*)(ip + 1);
            if ((void*)(tcp + 1) > data_end) return XDP_PASS;

            if (tcp->dest == __constant_htons(4040)) {
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
