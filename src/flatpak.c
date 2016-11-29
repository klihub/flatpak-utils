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


static int ftpk_init(flatpak_t *f)
{
    GError *e = NULL;

    if (f->f || (f->f = flatpak_installation_new_system(NULL, &e)))
        return 0;

    log_error("failed to initialize flatpak library (%s: %d:c%s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


void ftpk_forget(flatpak_t *f)
{
    flatpak_installation_drop_caches(f->f, NULL, NULL);
    g_object_unref(f->f);
    f->f = NULL;
}


int ftpk_discover_remotes(flatpak_t *f,
                          int (*cb)(flatpak_t *, FlatpakRemote *, const char *))
{
    GPtrArray     *arr;
    FlatpakRemote *r;
    const char    *name;
    GError        *e;
    int            i;

    if (ftpk_init(f) < 0)
        return -1;

    e   = NULL;
    arr = flatpak_installation_list_remotes(f->f, NULL, &e);

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

        if (cb(f, r, name) < 0)
            goto fail;
    }

    g_ptr_array_unref(arr);

    return 0;


 query_failed:
    log_error("failed to query flatpak remotes (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    g_ptr_array_unref(arr);

    return -1;
}


int ftpk_discover_apps(flatpak_t *f,
                       int (*cb)(flatpak_t *, FlatpakInstalledRef *,
                                 const char *, const char *, GKeyFile *))
{
    GPtrArray           *arr;
    FlatpakInstalledRef *ref;
    FlatpakRefKind       knd;
    const char          *origin, *name;
    GKeyFile            *meta;
    GError              *e;
    int                  i;

    if (ftpk_init(f) < 0)
        return -1;

    knd = FLATPAK_REF_KIND_APP;
    e   = NULL;
    arr = flatpak_installation_list_installed_refs_by_kind(f->f, knd, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        ref    = g_ptr_array_index(arr, i);
        origin = flatpak_installed_ref_get_origin(ref);

        if ((meta = ftpk_load_metadata(ref)) == NULL)
            goto fail;

        if ((name = ftpk_get_metadata(meta, "Application", "name")) == NULL) {
            log_warning("app without a name, ignoring...");
            continue;
        }

        if (cb(f, ref, name, origin, meta) < 0)
            goto fail;
    }

    g_ptr_array_unref(arr);

    return 0;

 query_failed:
    log_error("failed to query installed applications (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    return -1;
}


int ftpk_discover_updates(flatpak_t *f, const char *remote,
                          int (*cb)(flatpak_t *, FlatpakRemoteRef *,
                                    const char *, const char *, GKeyFile *))
{
    GPtrArray        *arr;
    FlatpakRemoteRef *ref;
    GKeyFile         *meta;
    const char       *origin, *name;
    GError           *e;
    int               i;

    if (ftpk_init(f) < 0)
        return -1;

    meta = NULL;
    e    = NULL;
    arr  = flatpak_installation_list_remote_refs_sync(f->f, remote, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        ref    = g_ptr_array_index(arr, i);
        origin = remote;
        name   = flatpak_ref_get_name(FLATPAK_REF(ref));

        if (flatpak_ref_get_kind(FLATPAK_REF(ref)) != FLATPAK_REF_KIND_APP)
            continue;

        meta = ftpk_fetch_metadata(f, origin, FLATPAK_REF(ref));

        if (meta == NULL)
            continue;

        if (cb(f, ref, name, origin, meta) < 0)
            goto fail;

        ftpk_unref_metadata(meta);
    }

    g_ptr_array_unref(arr);

    return 0;

 query_failed:
    log_error("failed to query pending updates/instals (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    ftpk_free_metadata(meta);
    return -1;
}


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


GKeyFile *ftpk_fetch_metadata(flatpak_t *f, const char *remote,
                              FlatpakRef *ref)
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
    bytes = flatpak_installation_fetch_remote_metadata_sync(f->f, remote, ref,
                                                            NULL, &e);

    if (bytes == NULL)
        goto fail_no_metadata;

    data = g_bytes_get_data(bytes, &size);

    if (!g_key_file_load_from_data(meta, data, size, 0, &e))
        goto fail_no_metadata;

    g_bytes_unref(bytes);

    return meta;

 fail_no_metadata:
    log_error("failed to fetch metadata for %s from %s (%s: %d: %s)",
              flatpak_ref_format_ref(ref), remote,
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    ftpk_free_metadata(meta);
    g_bytes_unref(bytes);

    return NULL;
}


const char *ftpk_get_metadata(GKeyFile *f, const char *section, const char *key)
{
    return g_key_file_get_value(f, section ? section : "Application", key, NULL);
}


static void update_progress_cb(const char *status, guint progress,
                               gboolean estim, gpointer user_data)
{
    application_t *app = user_data;

    UNUSED_ARG(estim);

    log_info("%s/%s: %s: %u %%...", app->origin, app->name, status, progress);
}


int ftpk_fetch_updates(flatpak_t *f, application_t *app)
{
    const char          *name  = app->name;
    FlatpakRefKind       kind  = FLATPAK_REF_KIND_APP;
    int                  flags = app->ref ? FLATPAK_UPDATE_FLAGS_NO_DEPLOY : 0;
    GError              *e     = NULL;
    FlatpakInstalledRef *upd;

    if (f->dry_run)
        return 0;

    upd = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                      update_progress_cb, app, NULL, &e);

    if (upd == NULL && e->code != 0)
        goto fetch_failed;

    if (upd == NULL || (app->ref != NULL && upd == app->ref))
        return 0;
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
        return 1;
    }

 fetch_failed:
    log_error("failed to fetch updates for %s/%s (%s: %d: %s)",
              app->origin, app->name,
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_apply_updates(flatpak_t *f, application_t *app)
{
    const char          *name  = app->name;
    FlatpakRefKind       kind  = FLATPAK_REF_KIND_APP;
    int                  flags = FLATPAK_UPDATE_FLAGS_NO_PULL;
    GError              *e     = NULL;
    FlatpakInstalledRef *u;

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == NULL && e->code != 0)
        goto fetch_failed;

    if (u == app->ref || u == NULL)
        return 0;
    else {
        g_object_unref(app->ref);
        app->ref = g_object_ref(u);

        ftpk_free_metadata(app->metadata);
        app->metadata = ftpk_load_metadata(app->ref);

        return 1;
    }

 fetch_failed:
    log_error("failed to fetch updates (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_update_app(flatpak_t *f, application_t *app)
{
    const char          *name  = app->name;
    FlatpakRefKind       kind  = FLATPAK_REF_KIND_APP;
    int                  flags = FLATPAK_UPDATE_FLAGS_NONE;
    GError              *e     = NULL;
    FlatpakInstalledRef *u;

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == NULL && e->code != 0)
        goto update_failed;

    if (u == app->ref || u == NULL)
        return 0;
    else {
        g_object_unref(app->ref);
        app->ref = g_object_ref(u);

        ftpk_free_metadata(app->metadata);
        app->metadata = ftpk_load_metadata(app->ref);

        return 1;
    }

 update_failed:
    log_error("update failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_launch_app(flatpak_t *f, application_t *app)
{
    GError *e;

    if (f->dry_run)
        return 0;

    e = NULL;
    if (!flatpak_installation_launch(f->f, app->name, NULL, NULL, NULL,
                                     NULL, &e))
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


int ftpk_signal_app(application_t *app, uid_t uid, pid_t session, int sig)
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

        log_info("sending process %u (%s) signal %d...", pid, exe, sig);

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


int ftpk_stop_app(application_t *app, uid_t uid, pid_t session)
{
    return ftpk_signal_app(app, uid, session, SIGTERM);
}


int ftpk_signal_session(uid_t uid, int sig)
{
    pid_t pid;

    if ((pid = ftpk_session_pid(uid)) == 0)
        return -1;

    return kill(pid, sig);
}
