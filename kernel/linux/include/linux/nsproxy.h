#ifndef _LINUX_NSPROXY_H
#define _LINUX_NSPROXY_H

struct mnt_namespace;
struct uts_namespace;
struct ipc_namespace;
struct pid_namespace;
struct net;

struct nsproxy
{
    atomic_t count;
    struct uts_namespace *uts_ns;
    struct ipc_namespace *ipc_ns;
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
    struct net *net_ns;
};
extern const struct nsproxy *init_nsproxy;

#endif //_LINUX_NSPROXY_H
