#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <asm/current.h>
#include <asm/thread_info.h>
#include <ktypes.h>
#include <ksyms.h>

extern void kfunc_def(__check_object_size)(const void *ptr, unsigned long n, bool to_user);
static inline void check_object_size(const void *ptr, unsigned long n, bool to_user)
{
    if (!__builtin_constant_p(n)) kfunc_call_void(__check_object_size, ptr, n, to_user);
}

static inline bool check_copy_size(const void *addr, size_t bytes, bool is_source)
{
    int sz = __builtin_object_size(addr, 0);
    if (unlikely(sz >= 0 && sz < bytes)) {
        if (!__builtin_constant_p(bytes)) logkw("Buffer overflow detected (%d < %lu)!\n", sz, bytes);
        return false;
    }
    check_object_size(addr, bytes, is_source);
    return true;
}

#endif