#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

struct super_block;
struct dentry;

struct vfsmount
{
    struct dentry *mnt_root; /* root of the mounted tree */
    struct super_block *mnt_sb; /* pointer to superblock */
    int mnt_flags;
};

#endif //_LINUX_MOUNT_H
