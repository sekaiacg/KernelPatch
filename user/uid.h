#ifndef _KPU_UID_H
#define _KPU_UID_H

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <linux/limits.h>
#include <fcntl.h>

#include "supercall.h"
#include "uid.h"
#include "profile.h"
#include "uapi/scdefs.h"

#define FILE_EVENT_MODIFY_MASK (IN_MODIFY | IN_MOVED_TO)
#define INOTIFY_EVENT_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

struct NotifyConf
{
    int inotifyFd;
    int epollFd;
    int maxNum;
    int eventMaxNum;
    int timeOut;
    struct epoll_event *epollEvents;
    struct epoll_event *inotifyEvent;
    int watchFd;
    bool initialized;
    bool monitorRun;
};

static inline bool init_inotify(struct NotifyConf *nf)
{
    bool ret = false;
    struct epoll_event *inotifyEvent = NULL;
    if (!nf->initialized) {
        nf->timeOut = -1;
        nf->eventMaxNum = 10;
        int watchFd = -1;
        nf->epollFd = epoll_create(2);
        if (nf->epollFd < 0) goto err;
        nf->inotifyFd = inotify_init();
        if (nf->inotifyFd < 0) goto err;
        nf->epollEvents = (struct epoll_event *)calloc(sizeof(struct epoll_event), nf->eventMaxNum);
        if (!nf->epollEvents) goto err;
        inotifyEvent = (struct epoll_event *)calloc(sizeof(struct epoll_event), 1);
        inotifyEvent->events = EPOLLIN | EPOLLET;
        inotifyEvent->data.fd = nf->inotifyFd;
        if (epoll_ctl(nf->epollFd, EPOLL_CTL_ADD, nf->inotifyFd, inotifyEvent) < 0) goto err;
        nf->initialized = true;
        ret = true;
        goto exit;
    }

err:
    if (nf->epollFd > 0) close(nf->epollFd);
    if (nf->inotifyFd > 0) close(nf->epollFd);
    if (nf->epollEvents) free(nf->epollEvents);
    if (inotifyEvent) free(inotifyEvent);
exit:
    return ret;
}

static inline bool add_packages_file_watch(struct NotifyConf *nf, const char *uidFilePath)
{
    bool ret = false;
    if (nf->initialized && nf->watchFd <= 0) {
        nf->watchFd = inotify_add_watch(nf->inotifyFd, uidFilePath, FILE_EVENT_MODIFY_MASK);
        return nf->watchFd > 0;
    }
    return ret;
}

static inline bool del_packages_file_watch(const struct NotifyConf *nf)
{
    if (nf->initialized) {
        inotify_rm_watch(nf->inotifyFd, nf->watchFd);
        return true;
    }
    return false;
}

static inline void uninit_inotify(struct NotifyConf *nf)
{
    if (nf->initialized) {
        del_packages_file_watch(nf);
        epoll_ctl(nf->epollFd, EPOLL_CTL_DEL, nf->inotifyFd, nf->epollEvents);
        close(nf->epollFd);
        close(nf->inotifyFd);
        free(nf->inotifyEvent);
        free(nf->epollEvents);
    }
}

static inline int notify_wait(const struct NotifyConf *nf)
{
    if (nf->initialized) {
        return epoll_wait(nf->epollFd, nf->epollEvents, nf->eventMaxNum, nf->timeOut);
    }
    return -1;
}

#define SYSTEM_PACKAGE_DIR "/data/system"
#define SYSTEM_PACKAGE_FILE "packages.list"

#define APATCH_PACKAGE_CONFIG_FILE "/data/adb/ap/package_config"

static inline char *get_package_buf()
{
    FILE *file = fopen(SYSTEM_PACKAGE_DIR "/" SYSTEM_PACKAGE_FILE, "rb");
    char *pkgListBuf = NULL;
    if (file) {
        fseek(file, 0, SEEK_END);
        size_t fileLen = ftell(file);
        fseek(file, 0, SEEK_SET);
        pkgListBuf = (char *)calloc(fileLen, 1);
        size_t redLen = fread(pkgListBuf, 1, fileLen, file);
        fclose(file);
        if (redLen == fileLen) {
            return pkgListBuf;
        }
        free(pkgListBuf);
    }
    return NULL;
}

static inline StringArray *get_pkg_config_list()
{
    StringArray *s = NULL;
    FILE *file = fopen(APATCH_PACKAGE_CONFIG_FILE, "rb");
    if (file) {
        char *buf = NULL;
        size_t len = 0, redLen = 0;
        s = initStringArray();
        while ((redLen = getline(&buf, &len, file)) != -1) {
            if (buf[redLen - 1] == '\n') buf[redLen - 1] = '\0';
            addStringToArray(s, buf);
        }
        if (buf) free(buf);
        fclose(file);
    }
    return s;
}

static inline void write_config(FILE *file, Pkg_Config *config)
{
    // FILE *file = fopen("/tmp/aaa/package_config1", "wb");
    // if (file) {
    // 	for (int i = 0; i < configs->size; ++i) {
    // 		fprintf(file, "%s\n", configs->data[i]);
    // 	}
    // 	fclose(file);
    // }
    fprintf(file, "%s,%d,%d,%u,%u,%s\n", config->pkgName, config->exclude, config->allow, config->uid, config->to_uid,
            config->sctx);
}

static inline void do_update_config(const char *key, PkgConfigArray *configs, bool needUpdate)
{
    if (needUpdate) {
        FILE *file = fopen(APATCH_PACKAGE_CONFIG_FILE, "wb");
        fprintf(file, "%s\n", "pkg,exclude,allow,uid,to_uid,sctx");
        if (file) {
            for (int i = 0; i < configs->size; ++i) {
                Pkg_Config *config = configs->pkg_configs[i];
                struct su_profile profile = {};
                switch (config->type) {
                case PKG_UID_UPDATE:
                    sc_su_revoke_uid(key, config->remove_uid);
                    profile.uid = config->remove_uid;
                    profile.to_uid = config->to_uid;
                    sc_su_grant_uid(key, profile.uid, &profile);
                case PKG_NONE:
                    //写到文件
                    write_config(file, config);
                    break;
                case PKG_REMOVE:
                    sc_su_revoke_uid(key, config->uid);
                    break;
                }
            }
            fclose(file);
        }
    }
}

static inline void update_config(const char *key)
{
    char *pkg_buf = get_package_buf();
    StringArray *configs = get_pkg_config_list();
    if (pkg_buf && configs) {
        bool needUpdate = false;
        int configSize = configs->size;

        PkgConfigArray *update_configs = initPkgConfigArray();

        for (int i = 0; i < configSize; ++i) {
            char *configStr = configs->data[i];
            if (!strncmp(configStr, "pkg,", 4) || configStr[0] == '#') {
                // addStringToArray(update_configs, configStr);
                continue;
            }
            Pkg_Config config = {};
            to_pkg_config(configStr, &config);

            char *foundInPkgList = strstr(pkg_buf, config.pkgName);
            if (foundInPkgList) {
                // pkgList
                uint32_t uidInPkgList = 0;
                sscanf(foundInPkgList, "%*s %u,", &uidInPkgList);
                if (config.uid == uidInPkgList) {
                    config.type = PKG_NONE;
                } else {
                    config.remove_uid = config.uid;
                    config.uid = uidInPkgList;
                    config.type = PKG_UID_UPDATE;
                    needUpdate = true;
                }
            } else {
                config.type = PKG_REMOVE;
                config.remove_uid = config.uid;
                needUpdate = true;
            }
            addPkgConfigToArray(update_configs, &config);
        }
        do_update_config(key, update_configs, needUpdate);
        freeStringArray(configs);
        freePkgConfigArray(update_configs);
        free(pkg_buf);
    }
}

static inline void handle_packages_list(const char *key, const struct inotify_event *ie)
{
    // printf("file detected: %s\n", ie->name);
    bool a = !strcmp(SYSTEM_PACKAGE_FILE, ie->name);
    if (!strcmp(SYSTEM_PACKAGE_FILE, ie->name)) {
        if (ie->mask & (IN_MODIFY | IN_MOVED_TO)) {
            printf("Config file changes detected: %s\n", SYSTEM_PACKAGE_FILE);
            update_config(key);
        }
    }
}

static inline void uid_monitor(const char *key, const struct NotifyConf *nf)
{
    prctl(PR_SET_NAME, "packages_monitor");
    char buf[INOTIFY_EVENT_BUF_LEN];
    ssize_t event_size = sizeof(struct inotify_event);
    struct epoll_event *event = nf->epollEvents;
    while (nf->monitorRun) {
        int event_count = notify_wait(nf);
        printf("FileObserver enter event\n");
        if (!nf->monitorRun) break;

        for (int i = 0; i < event_count; ++i) {
            int fd = event[i].data.fd;
            ssize_t len = 0;
            while ((len = read(fd, buf, INOTIFY_EVENT_BUF_LEN)) > 0) {
                ssize_t pos = 0;
                while (pos < len) {
                    struct inotify_event *inotifyEvent = (struct inotify_event *)&buf[pos];
                    handle_packages_list(key, inotifyEvent);
                    pos += event_size + inotifyEvent->len;
                }
            }
        }
    }
}

static inline int start_server(const char *key)
{
    int ret = false;
    static struct NotifyConf nf = {};
    bool err = init_inotify(&nf);
    if (!err) goto err;
    err = add_packages_file_watch(&nf, SYSTEM_PACKAGE_DIR);
    if (!err) goto err;
    nf.monitorRun = true;
    uid_monitor(key, &nf);
    uninit_inotify(&nf);
err:
    return ret;
}

static inline int start_uid_monitor(const char *key)
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    if (daemon(0, 0) == -1) {
        return -ENOEXEC;
    }
    while (true) {
        int status = 0;
        pid_t pid = -1;
        switch (pid = fork()) {
        case -1:
            return -ENOEXEC;
        case 0:
            return start_server(key);
        default:
            if (WIFEXITED(status) && pid == waitpid(pid, &status, 0)) {
                int exitCode = WEXITSTATUS(status);
                // printf("rret=%d %d %d\n", exitCode, getpid(), pid);
                if (exitCode == -ENODEV || exitCode == -ENOENT) {
                    return exitCode;
                }
            }
            sleep(1);
        }
    }
}
#endif //_KPU_UID_H
