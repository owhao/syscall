#ifndef HAVE_SYSCALL_H_
#define HAVE_SYSCALL_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

struct syscall_hook {
    char* name;
	int nr;
    void* old_addr;
    void* new_addr;
	bool hooked;
};

#define syscall_hook_entry(name) \
	{#name, __NR_##name, NULL, syscall_##name, false}

#define syscall_hook_end() \
	{NULL, 0, NULL, NULL, false}

#define syscall_hook_handler(ret, name) \
	static asmlinkage ret syscall_##name

#define syscall_hook_default(proto, name, ...) \
    ((proto)(syscall_hook_get(__NR_##name)->old_addr))(__VA_ARGS__)

int syscall_hook(struct syscall_hook hooks[]);
int syscall_unhook(void);
struct syscall_hook* syscall_hook_get(int nr);

#define syscall_log_emerg(msg, ...) \
    printk(KERN_EMERG "syscall <EMERG> " msg "\n", ##__VA_ARGS__);

#define syscall_log_alert(msg, ...) \
    printk(KERN_ALERT "syscall <ALERT> " msg "\n", ##__VA_ARGS__);

#define syscall_log_critical(msg, ...) \
    printk(KERN_CRIT "syscall <CRITICAL> " msg "\n", ##__VA_ARGS__);

#define syscall_log_error(msg, ...) \
    printk(KERN_ERR "syscall <ERROR> " msg "\n", ##__VA_ARGS__);

#define syscall_log_warning(msg, ...) \
    printk(KERN_WARNING "syscall <WARNING> " msg "\n", ##__VA_ARGS__);

#define syscall_log_notice(msg, ...) \
    printk(KERN_NOTICE "syscall <NOTICE> " msg "\n", ##__VA_ARGS__);

#define syscall_log_info(msg, ...) \
    printk(KERN_INFO "syscall <INFO> " msg "\n", ##__VA_ARGS__);

#define syscall_log_debug(msg, ...) \
    printk(KERN_DEBUG "syscall <DEBUG> " msg "\n", ##__VA_ARGS__);


#endif // HAVE_SYSCALL_H_
