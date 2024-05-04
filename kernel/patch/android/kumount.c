/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <accctl.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <hook.h>
#include <ktypes.h>
#include <kumount.h>
#include <predata.h>
#include <sucompat.h>
#include <taskext.h>

static bool is_appuid(uid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999

    uid_t appid = uid % PER_USER_RANGE;
    return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

static inline bool is_unsupported_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
    uid_t appid = uid % 100000;
    return appid > LAST_APPLICATION_UID;
}

/*
 * cap_task_fix_setuid - Fix up the results of setuid() call
 * @new: The proposed credentials
 * @old: The current task's current credentials
 * @flags: Indications of what has changed
 *
 * Fix up the results of setuid() call before the credential changes are
 * actually applied, returning 0 to grant the changes, -ve to deny them.
*/
//int cap_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
static void before_cap_task_fix_setuid(hook_fargs3_t *args, void *udata)
{
    const struct cred *new = (const struct cred *)args->arg0;
    const struct cred *old = (const struct cred *)args->arg1;

    if (!new || !old) {
        return;
    }

    uid_t new_uid = *(uid_t *)((uintptr_t)new + cred_offset.uid_offset);
    uid_t old_uid = *(uid_t *)((uintptr_t)old + cred_offset.uid_offset);

    if (0 != old_uid) {
        // old process is not root, ignore it.
        return;
    }

    if (!is_appuid(new_uid) || is_unsupported_uid(new_uid)) {
        logkfi("handle setuid ignore non application or isolated uid: %d\n", new_uid);
        return;
    }

    if (is_su_allow_uid(new_uid)) {
        logkfi("handle setuid ignore allowed application: %d\n", new_uid);
        return;
    }

    if (!uid_should_exclude(new_uid)) {
        return;
    } else {
        logkfi("uid: %d should not umount!\n", current_uid());
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    bool is_zygote_child = is_zygote(current);
    if (!is_zygote_child) {
        logkfi("handle umount ignore non zygote child: %d\n", current_ext->pid);
        return;
    }

    // umount the target mnt
    logkfi("handle umount for uid: %d, pid: %d\n", new_uid, current_ext->pid);

    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);

    // try umount temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH);
    try_umount("/sbin", false, MNT_DETACH);
}

int kp_umount_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    unsigned long cap_task_fix_setuid_addr = get_preset_patch_sym()->cap_task_fix_setuid;
    log_boot("cap_task_fix_setuid is at: %llx", cap_task_fix_setuid_addr);
    // TODO: Check addr validation
    rc = hook_wrap3((void *)cap_task_fix_setuid_addr, before_cap_task_fix_setuid, 0, 0);
    ret |= rc;
    log_boot("hook cap_task_fix_setuid rc: %d\n", rc);

    return ret;
}