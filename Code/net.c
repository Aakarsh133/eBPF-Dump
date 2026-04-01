#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, int);
    __uint(max_entries, 1);

}map1 SEC(".maps");

SEC("xdp")

int hello(void* ctx){

    __u32 key = 0;
    int *count_ptr;

    count_ptr = bpf_map_lookup_elem(&map1, &key);

    if (count_ptr){
        *count_ptr += 1;
        bpf_printk("Hello %d", *count_ptr);
    }    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

