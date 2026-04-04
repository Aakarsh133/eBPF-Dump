/*
Extract the pid of the current task, and then use BPF_CORE_READ(task, real_parent, pid) to get the parent's PID. 
Print both to the trace pipe: "PID 1234 was spawned by PID 1000".
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int get_process_parent_pid(void* ctx){
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *parent; 

    int err;

    err = bpf_core_read(&p, sizeof(void *), &task->parent);
    if (err){
        bpf_printk("Cannot load parent for %d", pid);
        return 0;

    }
    bpf_printk("PID %d was spawned by %d", pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";