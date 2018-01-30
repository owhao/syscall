* build
```shell
make
make load
dmesg | grep "syscall"
make unload
```

* sample
```c
#include "syscall.h"

static const char* get_process_name(int pid) {
    struct list_head* list;
    list_for_each(list, &current->tasks){
        struct task_struct *task = list_entry(list, struct task_struct, tasks);
        if (task->pid == pid)
            return task->comm;
    }

    return NULL;
}

syscall_hook_handler(long, kill)(int pid, int sig) {
    const char* name = get_process_name(pid);
    syscall_log_debug("mykill, pid: %d, sig: %d, name: %s", pid, sig, name);

    if (strcmp(name, "your_file") == 0) {
        return -EACCES;
    }

    return syscall_hook_default(asmlinkage long(*)(int, int), kill, pid, sig);
}

static struct syscall_hook hooks[] = {
    syscall_hook_entry(kill),
    syscall_hook_end()
};

static int __init sample_init(void) {
    int ret;

    syscall_log_info("sample init");

    ret = syscall_hook(hooks);
    if (ret < 0) {
        syscall_log_error("hook failed");
    }

    return ret;
}

static void __exit sample_exit(void) {
    syscall_unhook();
    syscall_log_info("sample exit");
}

module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");
```
