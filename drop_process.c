#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} allowed_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16]);
} target_process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

SEC("cgroup/skb")
int drop_process_traffic(struct __sk_buff *skb) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if this PID matches our target process
    int is_target_process = 0;
    for (__u32 i = 0; i < 1024; i++) {
        __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &i);
        if (!target_pid)
            break;
        if (*target_pid == pid) {
            is_target_process = 1;
            break;
        }
    }
    
    if (!is_target_process)
        return 1; // Allow traffic for other processes
    
    // Parse packet to check if it's TCP
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 1;
    
    if (ip->protocol != IPPROTO_TCP)
        return 1;
    
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return 1;
    
    // Get allowed port from map
    __u32 key = 0;
    __u32 *allowed_port = bpf_map_lookup_elem(&allowed_port_map, &key);
    if (!allowed_port)
        return 1;
    
    __u16 dest_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);
    
    // Allow traffic only on the specified port
    if (dest_port == *allowed_port || src_port == *allowed_port) {
        return 1; // Allow
    }
    
    // Drop all other traffic for this process
    return 0;
}

char _license[] SEC("license") = "GPL";