from time import sleep

from bcc import BPF


program = r"""
BPF_HASH(counter_table);

int hello(void* ctx){
    u64 pid;
    u64 counter = 0;
    u64 *p;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    p = counter_table.lookup(&pid);
    
    if (p != 0){
    counter = *p;
    }
    counter++;
    counter_table.update(&pid, &counter);
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event = syscall, fn_name="hello")

while True:
    sleep(2)
    s = ""

    for k, v in b["counter_table"].items():
        s += f"ID: {k.value}\t count: {v.value}\n"

    print(s)
