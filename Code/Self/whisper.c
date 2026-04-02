#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int counter = 0;

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx){
    if (ctx->id == 59){
        counter++;
        bpf_printk("Process spawned!! %d \n", counter);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";