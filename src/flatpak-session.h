/*
 * Copyright (c) 2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __FLATPAK_SESSION_H__
#define __FLATPAK_SESSION_H__

#include <stdio.h>
#include <sys/types.h>
#include <flatpak/flatpak.h>

#include "config.h"

/* default path definitions */
#ifndef SYSCONFDIR
#    define SYSCONFDIR "/etc"
#endif

#ifndef LIBDIR
#    define LIBDIR "/usr/lib"
#endif

#ifndef LIBEXECDIR
#    define LIBEXECDIR "/usr/libexec"
#endif

#ifndef SYSTEMD_SERVICEDIR
#    define SYSTEMD_SERVICEDIR LIBDIR"/systemd/system"
#endif

#ifndef FLATPAK_SESSION
#    define FLATPAK_SESSION "flatpak-session@.service"
#endif

#ifndef FLATPAK_TARGET
#    define FLATPAK_TARGET "flatpak-sessions.target"
#endif

#ifndef SYSTEMD_GENERATOR
#    define SYSTEMD_GENERATOR "flatpak-session-enable"
#endif

#ifndef SYSTEMD_USER_SLICE
#    define SYSTEMD_USER_SLICE "/sys/fs/cgroup/systemd/user.slice"
#endif

#ifndef FLATPAK_BWRAP
#    define FLATPAK_BWRAP "flatpak-bwrap"
#endif

#ifndef FLATPAK_SESSION_PATH
#    define FLATPAK_SESSION_PATH "/usr/bin/flatpak-session"
#endif

#ifndef FLATPAK_GECOS_PREFIX
#    define FLATPAK_GECOS_PREFIX "flatpak user for "
#endif

#define FLATPAK_POLL_MIN_INTERVAL /*(5 * 60)*/ 15


/* mark unused arguments and silence the compiler about them */
#define UNUSED_ARG(arg) (void)arg

/* commands/modes of operation */
typedef enum {
    COMMAND_UNKNOWN = -1,
    COMMAND_NONE,
    COMMAND_LIST,                        /* list sessions, users and flatpaks */
    COMMAND_GENERATE,                    /* generate a systemd session */
    COMMAND_START,                       /* start flatpaks for a session */
    COMMAND_STOP,                        /* stop flatpaks for a session */
    COMMAND_SIGNAL,                      /* signal a flatpak session */
    COMMAND_FETCH,                       /* fetch updates from remotes */
    COMMAND_APPLY,                       /* update flatpaks from local cache */
    COMMAND_UPDATE,                      /* fetch updates and apply them */
} command_t;

/* runtime context */
typedef struct flatpak_s flatpak_t;
struct flatpak_s {
    FlatpakInstallation *f;              /* flatpak context */
    GHashTable          *remotes;        /* remotes for applications */
    GHashTable          *apps;           /* installed applications */
    GMainLoop           *loop;           /* main loop */
    void               (*sighandler)(flatpak_t *f, int sig);
    int                  sfd;            /* signalfd */
    GIOChannel          *sio;            /* GIOChannel for our signalfd */
    guint                sid;            /* GIOChannel watch source id */
    void               (*monitor)(flatpak_t *f);
    guint                mid;            /* monitoring timer source id */
    int                  exit_code;      /* exit code to exit with */
    const char          *argv0;          /* us... */
    const char          *dir_service;    /* systemd generator service dir. */
    uid_t                user;           /* user id to stop session for */
    int                  sig;            /* signal to send to a session */
    command_t            command;        /* action to perform */
    char               **chosen;         /* remotes given on commandline */
    int                  nchosen;        /* number of chosen remotes */
    int                  restart_status; /* exit status for forced restart */
    int                  poll_interval;  /* update polling interval */
    int                  dry_run : 1;    /* don't perform, just show actions */
    int                  gpg_verify : 1; /* ignore unverifiable remotes */
    int                  updating : 1;   /* busy fetching/applying updates */
};

/* a remote repository for applications */
typedef struct {
    FlatpakRemote *r;                    /* flatpak remote */
    const char    *name;                 /* remote name */
    uid_t          uid;                  /* associated user for session */
} remote_t;

/* an installed application */
typedef struct {
    FlatpakInstalledRef *app;            /* flatpak application */
    const char          *origin;         /* application origin (remote name) */
    GKeyFile            *metadata;       /* application metadata */
    const char          *name;           /* application name */
    const char          *urgency;        /* update urgency */
    int                  autostart : 1;  /* whether to autostart */
} application_t;

/*
 * function prototypes
 */

/* log.c */
extern int log_fd;
extern int log_mask;

#define log(fmt, args...) do {                                \
        dprintf(log_fd, fmt"\n", ## args);                    \
    } while (0)


#define log_debug(fmt, args...)   log("D: [%s:%d] "fmt, \
                                      __FILE__, __LINE__, ##args)
#define log_info(fmt, args...)    log("I: "fmt, ##args)
#define log_warning(fmt, args...) log("W: "fmt, ##args)
#define log_error(fmt, args...)   log("E: "fmt, ##args)

void log_open(flatpak_t *f);

/* config.c */
void config_parse_cmdline(flatpak_t *f, int argc, char **argv);

/* mainloop.c */
void mainloop_create(flatpak_t *f);
void mainloop_destroy(flatpak_t *f);
void mainloop_run(flatpak_t *f);
void mainloop_quit(flatpak_t *f, int exit_code);
int mainloop_watch_signals(flatpak_t *f, sigset_t *ss,
                           void (*h)(flatpak_t *, int));
void mainloop_ditch_signals(flatpak_t *f);
int mainloop_enable_monitor(flatpak_t *f, void (*cb)(flatpak_t *));
void mainloop_disable_monitor(flatpak_t *f);


/* flatpak.c */
void ftpk_exit(flatpak_t *f);
int ftpk_discover_remotes(flatpak_t *f);
int ftpk_discover_apps(flatpak_t *f);
remote_t *ftpk_remote(flatpak_t *f, const char *name);
application_t *ftpk_app(flatpak_t *f, const char *name);
int ftpk_launch_app(flatpak_t *f, application_t *app);

int ftpk_fetch_updates(flatpak_t *f, application_t *app);
int ftpk_apply_updates(flatpak_t *f, application_t *app);
int ftpk_update_app(flatpak_t *f, application_t *app);
int ftpk_signal_app(flatpak_t *f, application_t *app, uid_t uid, pid_t session,
                    int sig);
int ftpk_stop_app(flatpak_t *f, application_t *app, uid_t uid, pid_t session);
GKeyFile *ftpk_load_metadata(FlatpakInstalledRef *r);
void ftpk_free_metadata(GKeyFile *f);
const char *ftpk_get_metadata(GKeyFile *f, const char *section, const char *key);

/* remote.c */
int remote_discover(flatpak_t *f);
uid_t remote_resolve_user(const char *name, char *buf, size_t size);
remote_t *remote_lookup(flatpak_t *f, const char *name);
const char *remote_username(remote_t *r, char *buf, size_t size);
remote_t *remote_for_user(flatpak_t *f, uid_t uid);

/* application.c */
int app_discover(flatpak_t *f);
int app_fetch_updates(flatpak_t *f, application_t *app);
int app_update_cached(flatpak_t *f, application_t *app);
int app_fetch(flatpak_t *f);
int app_update(flatpak_t *f);

/* session.c */
int session_enable(flatpak_t *f);
int session_list(flatpak_t *f);
int session_start(flatpak_t *f);
int session_stop(flatpak_t *f);
int session_signal(flatpak_t *f);

/* filesystem.c */
int fsys_prepare_sessions(flatpak_t *f);
char *fsys_mkpath(char *path, size_t size, const char *fmt, ...);
int fsys_mkdir(const char *path, mode_t mode);
int fsys_mkdirp(mode_t, const char *fmt, ...);
int fsys_symlink(const char *path, const char *dst);
char *fsys_service_path(flatpak_t *f, const char *usr, char *path, size_t size);
char *fsys_service_link(flatpak_t *f, const char *usr, char *path, size_t size);
int fs_scan_proc(const char *exe, uid_t uid,
                 int (*cb)(pid_t pid, void *user_data), void *user_data);

#endif /* __FLATPAK_SESSION_H__ */
