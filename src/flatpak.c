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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>

#include "flatpak-session.h"


static void r_free(gpointer data)
{
    remote_t *r = data;

    if (r == NULL)
        return;

    g_object_unref(r->r);

    free(r);
}


static void a_free(gpointer data)
{
    application_t *a = data;

    if (a == NULL)
        return;

    g_object_unref(a->app);
    ftpk_free_metadata(a->metadata);

    free(a);
}


static int ftpk_init(flatpak_t *f)
{
    GError *e = NULL;

    if (f->f || (f->f = flatpak_installation_new_system(NULL, &e)))
        return 0;

    log_error("failed to initialize flatpak library (%s: %d:c%s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


void ftpk_exit(flatpak_t *f)
{
    g_object_unref(f->f);
    g_hash_table_destroy(f->remotes);
    g_hash_table_destroy(f->apps);

    f->f       = NULL;
    f->remotes = NULL;
    f->apps    = NULL;
}


int ftpk_discover_remotes(flatpak_t *f)
{
    GPtrArray     *arr;
    remote_t      *remote;
    FlatpakRemote *r;
    const char    *name;
    uid_t          uid;
    GError        *e;
    int            i, j, match;

    if (ftpk_init(f) < 0)
        return -1;

    if (f->remotes != NULL)
        return 0;

    f->remotes = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_free);

    if (f->remotes == NULL)
        return -1;

    remote = NULL;
    e      = NULL;
    arr    = flatpak_installation_list_remotes(f->f, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        r    = g_ptr_array_index(arr, i);
        name = flatpak_remote_get_name(r);

        if (flatpak_remote_get_disabled(r)) {
            log_warning("remote %s: disabled, ignoring...", name);
            continue;
        }

        if (!flatpak_remote_get_gpg_verify(r) && f->gpg_verify) {
            log_warning("remote %s: can't be GPG-verified, ignorging...", name);
            continue;
        }

        if ((uid = remote_resolve_user(name, NULL, 0)) == (uid_t)-1) {
            log_warning("remote %s: no associated user, ignoring...", name);
            continue;
        }

        if (f->nchosen > 0) {
            for (j = 0, match = 0; !match && j < (int)f->nchosen; j++) {
                if (!strcmp(f->chosen[j], name))
                    match = 1;
            }
        }
        else
            match = 1;

        if (!match) {
            log_warning("remote %s: not a selected remote, ignoring...", name);
            continue;
        }

        if ((remote = calloc(1, sizeof(*remote))) == NULL)
            goto fail;

        remote->r    = g_object_ref(r);
        remote->name = name;
        remote->uid  = uid;

        if (!g_hash_table_insert(f->remotes, (void *)name, remote))
            goto fail;

        log_info("discovered remote %s", remote->name);
    }

    g_ptr_array_unref(arr);

    return 0;


 query_failed:
    log_error("failed to query flatpak remotes (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    r_free(remote);
    g_hash_table_destroy(f->remotes);
    f->remotes = NULL;

    return -1;
}


int ftpk_discover_apps(flatpak_t *f)
{
    GPtrArray           *arr;
    FlatpakInstalledRef *ref;
    FlatpakRefKind       knd;
    remote_t            *remote;
    application_t       *app;
    const char          *origin, *name;
    GKeyFile            *meta;
    GError              *e;
    int                  i;

    if (ftpk_init(f) < 0)
        return -1;

    if (ftpk_discover_remotes(f) < 0)
        return -1;

    if (f->apps != NULL)
        return 0;

    f->apps = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, a_free);

    if (f->apps == NULL)
        return -1;

    app = NULL;
    knd = FLATPAK_REF_KIND_APP;
    e   = NULL;
    arr = flatpak_installation_list_installed_refs_by_kind(f->f, knd, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        app    = NULL;
        ref    = g_ptr_array_index(arr, i);
        origin = flatpak_installed_ref_get_origin(ref);
        remote = ftpk_remote(f, origin);

        if (remote == NULL)
            continue;

        if ((meta = ftpk_load_metadata(ref)) == NULL)
            goto fail;

        if ((name = ftpk_get_metadata(meta, "Application", "name")) == NULL)
            continue;

        if ((app = calloc(1, sizeof(*app))) == NULL)
            goto fail;

        app->app      = g_object_ref(ref);
        app->origin   = origin;
        app->metadata = meta;
        app->name     = name;

        if (!g_hash_table_insert(f->apps, (void *)app->name, app))
            goto fail;

        log_info("discovered application %s/%s", app->origin, app->name);
    }

    g_ptr_array_unref(arr);

    return 0;

 query_failed:
    log_error("failed to query installed applications (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    a_free(app);
    g_hash_table_destroy(f->apps);
    f->apps = NULL;

    return -1;
}


remote_t *ftpk_remote(flatpak_t *f, const char *name)
{
    return f && f->remotes ? g_hash_table_lookup(f->remotes, name) : NULL;
}


application_t *ftpk_app(flatpak_t *f, const char *name)
{
    return f && f->apps ? g_hash_table_lookup(f->apps, name) : NULL;
}


#if 0
int ftpk_discover_remotes(flatpak_t *f)
{
    FlatpakRemote *r;
    GPtrArray     *remotes;
    const char    *name;
    GError        *e;
    int            i, j, match;

    if (ftpk_init(f) < 0)
        goto fail;

    e       = NULL;
    remotes = flatpak_installation_list_remotes(f->f, NULL, &e);

    if (remotes == NULL)
        goto query_failed;

    for (i = 0; i < (int)remotes->len; i++) {
        r    = g_ptr_array_index(remotes, i);
        name = flatpak_remote_get_name(r);

        log_info("discovered remote '%s' (%s)", name, flatpak_remote_get_url(r));

        if (flatpak_remote_get_disabled(r)) {
            log_warning("    is disabled, skipping...");
            goto discard;
        }

        if (!flatpak_remote_get_gpg_verify(r)) {
            log_warning("    can't be GPG-verified%s...",
                        f->gpg_verify ? ", skipping" : "");
            if (f->gpg_verify)
                goto discard;
        }

        for (j = 0, match = 0; !match && j < (int)f->nchosen; j++) {
            if (!strcmp(f->chosen[j], name))
                match = 1;
        }

        if (!match && f->chosen != NULL) {
            log_warning("    not selected, skipping...");

        discard:
            g_ptr_array_remove_index_fast(remotes, (guint)i);
            i--;
        }
    }

    f->f_remotes = remotes;
    return 0;

 query_failed:
    log_error("failed to query remotes (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    return -1;
}


int ftpk_discover_apps(flatpak_t *f)
{
    FlatpakInstalledRef *a;
    FlatpakRefKind       knd;
    remote_t            *r;
    const char          *o;
    GPtrArray           *apps;
    GError              *e;
    int                  i;

    if (ftpk_init(f) < 0)
        goto fail;

    knd  = FLATPAK_REF_KIND_APP;
    e    = NULL;
    apps = flatpak_installation_list_installed_refs_by_kind(f->f, knd, NULL, &e);

    if (apps == NULL)
        goto query_failed;

    for (i = 0; i < (int)apps->len; i++) {
        a = g_ptr_array_index(apps, i);
        o = flatpak_installed_ref_get_origin(a);
        r = remote_lookup(f, o);

        if (r == NULL) {
            log_warning("ignoring app without associated session remote...");
            g_ptr_array_remove_index_fast(apps, (guint)i);
            i--;
            continue;
        }
    }

    f->f_apps = apps;
    return 0;

 query_failed:
    log_warning("failed to query installed apps (%s: %d:%s)",
                g_quark_to_string(e->domain), e->code, e->message);

 fail:
    return -1;
}

#endif

GKeyFile *ftpk_load_metadata(FlatpakInstalledRef *r)
{
    GKeyFile   *meta;
    GBytes     *bytes;
    const void *data;
    size_t      size;
    GError     *e;

    meta = g_key_file_new();

    if (meta == NULL)
        goto fail;

    e     = NULL;
    bytes = flatpak_installed_ref_load_metadata(r, NULL, &e);

    if (bytes == NULL)
        goto fail_no_metadata;

    data = g_bytes_get_data(bytes, &size);

    if (!g_key_file_load_from_data(meta, data, size, 0, &e))
        goto fail_no_metadata;

    g_bytes_unref(bytes);

    return meta;

 fail_no_metadata:
    log_error("failed to load application metadata (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    ftpk_free_metadata(meta);
    g_bytes_unref(bytes);
    return NULL;
}


void ftpk_free_metadata(GKeyFile *meta)
{
    if (meta != NULL)
        g_key_file_unref(meta);
}


const char *ftpk_get_metadata(GKeyFile *f, const char *section, const char *key)
{
    return g_key_file_get_value(f, section, key, NULL);
}


static void update_progress_cb(const char *status, guint progress,
                               gboolean estim, gpointer user_data)
{
    application_t *app = user_data;

    UNUSED_ARG(estim);

    log_info("upading %s/%s: %s: %u %%...", app->origin, app->name,
             status, progress);
}


int ftpk_fetch_updates(flatpak_t *f, application_t *app)
{
    const char          *origin = app->origin;
    const char          *name   = app->name;
    FlatpakRefKind       kind   = FLATPAK_REF_KIND_APP;
    int                  flags  = FLATPAK_UPDATE_FLAGS_NO_DEPLOY;
    GError              *e      = NULL;
    FlatpakInstalledRef *u;

    log_info("fetching updates for application %s/%s...", origin, name);

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == NULL && e->code != 0)
        goto fetch_failed;

    if (u == app->app || u == NULL)
        log_info("no pending updates");
    else {
        /*
         * Unfortunately libflatpak seems to have a bug related to updates
         * which are fetched with the NO_DEPLOY flag. While the updated
         * FlatpakInstalledRef has correct commit info, its deploy-dir
         * still points to the old, currently active one. This prevents us
         * from easily (IOW using stock flatpak functions) getting to the
         * metadata of the freshly downloaded HEAD.
         *
         * In practice this means that we cannot check our extra set of
         * metadata (for instance urgency) without applying the updates
         * first...
         */
        log_info("updates for %s/%s fetched succesfully", origin, name);
    }

    return 0;

 fetch_failed:
    log_error("failed to fetch updates (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_apply_updates(flatpak_t *f, application_t *app)
{
    const char          *origin = app->origin;
    const char          *name   = app->name;
    FlatpakRefKind       kind   = FLATPAK_REF_KIND_APP;
    int                  flags  = FLATPAK_UPDATE_FLAGS_NO_PULL;
    GError              *e      = NULL;
    FlatpakInstalledRef *u;

    log_info("applying pending updates for application %s/%s...", origin, name);

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == NULL && e->code != 0)
        goto fetch_failed;

    if (u == app->app || u == NULL)
        log_info("no pending updates");
    else {
        log_info("updates for %s/%s applied succesfully", origin, name);

        g_object_unref(app->app);
        app->app = g_object_ref(u);

        ftpk_free_metadata(app->metadata);
        app->metadata = ftpk_load_metadata(app->app);
    }

    return 0;

 fetch_failed:
    log_error("failed to fetch updates (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_update_app(flatpak_t *f, application_t *app)
{
    const char          *origin = app->origin;
    const char          *name   = app->name;
    FlatpakRefKind       kind   = FLATPAK_REF_KIND_APP;
    int                  flags  = FLATPAK_UPDATE_FLAGS_NONE;
    GError              *e      = NULL;
    FlatpakInstalledRef *u;

    log_info("checking updates for application %s/%s...", origin, name);

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == NULL && e->code != 0)
        goto update_failed;

    if (u == app->app || u == NULL)
        log_info("%s/%s is already up-to-date", app->origin, name);
    else {
        log_info("%s/%s updated successfully.", app->origin, name);

        g_object_unref(app->app);
        app->app = g_object_ref(u);

        ftpk_free_metadata(app->metadata);
        app->metadata = ftpk_load_metadata(app->app);
    }

    return 0;

 update_failed:
    log_error("update failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_launch_app(flatpak_t *f, application_t *app)
{
    GError *e;
    int     s;

    log_info("launching application %s/%s...", app->origin, app->name);

    if (f->dry_run)
        return 0;

    e = NULL;
    sigprocmask(SIG_UNBLOCK, &f->blocked, NULL);
    s = flatpak_installation_launch(f->f, app->name, NULL, NULL, NULL, NULL, &e);
    sigprocmask(SIG_BLOCK, &f->blocked, NULL);

    if (!s)
        goto launch_failed;

    return 0;

 launch_failed:
    log_error("failed to launch application '%s' (%s: %d:%s).", app->name,
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


static char *ftpk_scope(uid_t uid, pid_t session, const char *app,
                        char *buf, size_t size)
{
    int n;

    if (uid == (uid_t)-1)
        uid = geteuid();
    if (session == 0)
        session = getpid();

    n = snprintf(buf, size,
                 "%s/user-%u.slice/user@%u.service/flatpak-%s-%u.scope",
                 SYSTEMD_USER_SLICE, uid, uid, app, session);

    if (n < 0 || n >= (int)size)
        return NULL;

    return buf;
}


static int check_pid_cb(pid_t pid, void *user_data)
{
    pid_t *pidp = user_data;

    if (pid == *pidp)
        return 1;

    *pidp = pid;
    return 0;
}


pid_t ftpk_session_pid(uid_t uid)
{
    pid_t pid, own;

    pid = own = getpid();

    if (fs_scan_proc(FLATPAK_SESSION_PATH, uid, check_pid_cb, &pid) < 0)
        return 0;

    return pid != own ? pid : 0;
}


int ftpk_signal_app(flatpak_t *f, application_t *app, uid_t uid, pid_t session,
                    int sig)
{
    char  tasks[PATH_MAX], scope[PATH_MAX], exe[PATH_MAX], lnk[PATH_MAX];
    char  task[32], *base;
    pid_t pid;
    FILE *fp;
    int   n, status;

    if (session == 0)
        session = getpid();

    n = snprintf(tasks, sizeof(tasks), "%s/tasks",
                 ftpk_scope(uid, session, app->name, scope, sizeof(scope)));

    if (n < 0 || n >= (int)sizeof(tasks))
        goto nametoolong;

    if ((fp = fopen(tasks, "r")) == NULL)
        goto failed;

    status = 0;
    while (fgets(task, sizeof(task), fp) != NULL) {
        pid = strtoul(task, NULL, 10);
        snprintf(lnk, sizeof(lnk), "/proc/%u/exe", (unsigned int)pid);

        if ((n = readlink(lnk, exe, sizeof(exe))) < 0)
            continue;

        exe[n] = '\0';

        if ((base = strrchr(exe, '/')) != NULL)
            base++;
        else
            base = exe;

        if (!strcmp(base, FLATPAK_BWRAP))
            continue;

        log_info("Sending process %u (%s) signal %d (%s)...",
                 pid, exe, sig, strsignal(sig));

        if (!f->dry_run)
            if (kill(pid, sig) < 0)
                status = -1;
    }

    fclose(fp);

    return status;

 nametoolong:
    errno = ENAMETOOLONG;
    return -1;

 failed:
    return -1;
}


int ftpk_stop_app(flatpak_t *f, application_t *app, uid_t uid, pid_t session)
{
    return ftpk_signal_app(f, app, uid, session, SIGTERM);
}


int ftpk_signal_session(uid_t uid, int sig)
{
    pid_t pid;

    log_info("sending signal #%d to session for user %d...", sig, uid);

    if ((pid = ftpk_session_pid(uid)) == 0)
        return -1;

    printf("session pid is %d\n", pid);

    return kill(pid, sig);
}
