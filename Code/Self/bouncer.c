#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct hdr_pos{
    void *pos;
};

static __always_inline int parse_ipv6(struct hdr_pos *nh, void *data_end, struct iphdr **iph){
    struct iphdr *ip = nh->pos;
    int size = sizeof(struct iphdr);

    if (nh->pos + size > data_end){
        return -1;
    }
    nh->pos += size;
    *iph = ip;

    return ip->protocol;
}

static __always_inline int parse_ethhdr(struct hdr_pos *nh, void *data_end, struct ethhdr **ethhdr){
    struct ethhdr *eth = nh->pos;
    int size = sizeof(struct ethhdr);

    if (nh->pos + size > data_end){
        return -1;
    } 
    nh->pos += size;
    *ethhdr = eth;

    return eth->h_proto;
}

SEC("xdp")
int halt_ping_request(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;

    struct hdr_pos nh;
    int nh_type;
    nh.pos = data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type != bpf_htons(0x0800)) {
        //bpf_printk("Not IPV6");
        return XDP_PASS;
    }

    struct iphdr *ip4;

    int ph_type;
    ph_type = parse_ipv6(&nh, data_end, &ip4);
    if (ph_type == 1){
        bpf_printk("Ping Ponged!");
        return XDP_DROP;
    }


    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";