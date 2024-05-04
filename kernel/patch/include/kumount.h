#ifndef _KP_MOUNT_H_
#define _KP_MOUNT_H_

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/nsproxy.h>
#include <linux/security.h>
#include <linux/string.h>

#include <log.h>
#include <symbol.h>

static inline struct nsproxy *get_nsproxy()
{
    struct nsproxy *nsproxy = *(struct nsproxy **)((uintptr_t)current + task_struct_offset.nsproxy_offset);
    return nsproxy;
}

static inline uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;
}

static inline bool is_zygote(struct task_struct *task)
{
    u32 secid;
    char *domain;
    u32 seclen;
    security_task_getsecid(task, &secid);
    int err = security_secid_to_secctx(secid, &domain, &seclen);
    if (err) {
        return false;
    }
    bool ret = strncmp("u:r:zygote:s0", domain, seclen) == 0;
    security_release_secctx(domain, seclen);
    return ret;
}

static inline bool should_umount(struct path *path)
{
    if (!path) {
        return false;
    }

    if (get_nsproxy()->mnt_ns == init_nsproxy->mnt_ns) {
        logke("ignore global mnt namespace process: %d\n", current_uid());
        return false;
    }

    if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
        const char *fstype = path->mnt->mnt_sb->s_type->name;
        return strcmp(fstype, "overlay") == 0;
    }
    return false;
}

static inline int umount_mnt(struct path *path, int flags)
{
    if (kver >= VERSION(5, 9, 0)) {
        return path_umount(path, flags);
    } else {
        return -ENOSYS;
    }
}

static void try_umount(const char *mnt, bool check_mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry != path.mnt->mnt_root) {
        // it is not root mountpoint, maybe umounted by others already.
        return;
    }

    // we are only interest in some specific mounts
    if (check_mnt && !should_umount(&path)) {
        return;
    }

    err = umount_mnt(&path, flags);
    if (err) {
        logkw("umount %s failed: %d\n", mnt, err);
    }
}
KP_EXPORT_SYMBOL(try_umount);

#endif //_KP_MOUNT_H_
