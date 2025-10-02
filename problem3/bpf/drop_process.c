#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>   // <-- needed for bpf_htons

// Map for storing the allowed process name
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);     // always 0
    __type(value, char[16]); // allowed process name
    __uint(max_entries, 1);
} proc_name_map SEC(".maps");

// Map for storing the allowed TCP port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // always 0
    __type(value, __u16); // allowed port
    __uint(max_entries, 1);
} port_map SEC(".maps");

// Attach to cgroup connect4 hook
SEC("cgroup/connect4")
int allow_process_connect(struct bpf_sock_addr *ctx) {
    __u32 key = 0;

    // Lookup allowed process name
    char *allowed_proc = bpf_map_lookup_elem(&proc_name_map, &key);
    if (!allowed_proc)
        return 0; // reject

    // Lookup allowed port
    __u16 *allowed_port = bpf_map_lookup_elem(&port_map, &key);
    if (!allowed_port)
        return 0; // reject

    // Get current process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check process + port match
    if (__builtin_memcmp(comm, allowed_proc, 16) == 0 &&
        ctx->user_port == bpf_htons(*allowed_port)) {
        return 1; // allow
    }

    return 0; // reject
}

char _license[] SEC("license") = "GPL";
