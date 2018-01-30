#include "syscall.h"

#define BUF_SIZE 256
static void** syscall_tables = NULL;
static struct syscall_hook* syscall_hooks = NULL;

static char* syscall_get_kernel_version(char* buf, size_t length) {
    char *kernel_version = NULL;
    struct file *file = NULL;

    file = filp_open("/proc/version", O_RDONLY, 0);
    if (IS_ERR(file) || NULL == file) {
        return NULL;
    }

    memset(buf, 0, length);

    vfs_read(file, buf, length, &(file->f_pos));

    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");

    filp_close(file, 0);

    return kernel_version;
}

static void** syscall_get_syscall_tables(char* kernel_version) {
    char buf[BUF_SIZE];
    size_t buf_offset = 0;
    const char filename_prefix[] = "/boot/System.map-";
    struct file *file = NULL;
    char *filename = NULL;
    void *table = NULL;
    int ret;

    size_t filename_length = strlen(kernel_version)
                             + strlen(filename_prefix)
                             + 1;

    filename = kmalloc(filename_length, GFP_KERNEL);
    if (NULL == filename) {
        return NULL;
    }

    memset(filename, 0, filename_length);

    strncpy(filename, filename_prefix, strlen(filename_prefix));
    strncat(filename, kernel_version, strlen(kernel_version));

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file) || NULL == file) {
        kfree(filename);
        return NULL;
    }

    memset(buf, 0, BUF_SIZE);

    while (vfs_read(file, buf + buf_offset, 1, &file->f_pos) == 1) {
        if (buf_offset == BUF_SIZE - 1 || buf[buf_offset] == '\n') {
            if (strstr(buf, "sys_call_table") != NULL) {
                char *ptr = buf;
                char *addr = strsep(&ptr, " ");
                if (NULL != addr) {
                    ret = kstrtoul(addr, 16, (unsigned long*)&table);
                }

                break;
            }

            memset(buf, 0, BUF_SIZE);
            buf_offset = 0;
            continue;
        }

        ++buf_offset;
    }

    filp_close(file, 0);
    kfree(filename);

    return (void **)table;
}

static int syscall_lazy(void) {
    if (NULL == syscall_tables) {
        char buf[BUF_SIZE], *kernel_version = NULL;
        mm_segment_t seg;

        seg = get_fs();
        set_fs(KERNEL_DS);

        kernel_version = syscall_get_kernel_version(buf, BUF_SIZE);
        if (NULL != kernel_version) {
            syscall_tables = syscall_get_syscall_tables(kernel_version);
        }

        set_fs(seg);
    }

    return (syscall_tables ? 0 : -EFAULT);
}

int syscall_hook(struct syscall_hook hooks[]) {
    int ret;
    struct syscall_hook *entry;

    if (syscall_hooks) {
        return -EALREADY;
    }

    ret = syscall_lazy();
    if (ret) {
        return ret;
    }

    syscall_hooks = hooks;

    write_cr0 (read_cr0 () & (~ 0x10000));

    for (entry = hooks; entry->name; ++entry) {
        if (!entry->hooked) {
            entry->old_addr = (void *)syscall_tables[entry->nr];
            syscall_tables[entry->nr] = entry->new_addr;
            entry->hooked = true;
        }
    }

    write_cr0 (read_cr0 () | 0x10000);

    return 0;
}

int syscall_unhook(void) {
    if (syscall_tables && syscall_hooks) {
        struct syscall_hook *entry;

        write_cr0 (read_cr0 () & (~ 0x10000));

        for (entry = syscall_hooks; entry->name; ++entry) {
            if (entry->hooked) {
                syscall_tables[entry->nr] = entry->old_addr;
                entry->hooked = false;
            }
        }

        write_cr0 (read_cr0 () | 0x10000);
    }

    return 0;
}

struct syscall_hook* syscall_hook_get(int nr) {
    if (syscall_hooks) {
        struct syscall_hook *entry;
        for (entry = syscall_hooks; entry->name; ++entry) {
            if (entry->nr == nr)
                return entry;
        }
    }

    return NULL;
}
