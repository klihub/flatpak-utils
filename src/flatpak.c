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


static void metadata_free(GKeyFile *m);


static void remote_free(gpointer ptr)
{
    remote_t *r = ptr;

    if (r == NULL)
        return;

    g_object_unref(r->r);
    free(r);
}


static void app_free(gpointer ptr)
{
    application_t *a = ptr;

    if (a == NULL)
        return;

    g_object_unref(a->lref);
    g_object_unref(a->rref);
    metadata_free(a->meta);

    free(a);
}


static int ftpk_init(flatpak_t *f)
{
    GError *e;

    if (f->f != NULL)
        return 0;

    e    = NULL;
    f->f = flatpak_installation_new_system(NULL, &e);

    if (f->f == NULL)
        goto fail;

#define r_free remote_free
#define a_free app_free
    f->remotes = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_free);
    f->apps    = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, a_free);
#undef r_free
#undef a_free

    if (f->remotes == NULL || f->apps == NULL)
        goto fail;

    return 0;

 fail:
    log_error("flatpak library failed to initialize (%s: %d: %s)",
              e ? g_quark_to_string(e->domain) : "libc",
              e ? e->code                      : errno,
              e ? e->message                   : strerror(errno));
    ftpk_exit(f);

    return -1;
}


void ftpk_reset(flatpak_t *f)
{
    ftpk_forget_remotes(f);
    ftpk_forget_apps(f);
}


void ftpk_exit(flatpak_t *f)
{
    ftpk_reset(f);
    g_object_unref(f->f);
    f->f = NULL;
}


int ftpk_discover_remotes(flatpak_t *f)
{
    GPtrArray     *arr;
    GError        *e;
    remote_t      *r;
    FlatpakRemote *rem;
    const char    *name, *url;
    uid_t          uid;
    int            i;

    if (f->remotes != NULL)
        return 0;

    if (ftpk_init(f) < 0)
        return -1;

    r   = NULL;
    e   = NULL;
    arr = flatpak_installation_list_remotes(f->f, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        rem  = g_ptr_array_index(arr, i);
        name = flatpak_remote_get_name(rem);
        url  = flatpak_remote_get_url(rem);

        if (flatpak_remote_get_disabled(rem)) {
            log_warning("remote %s: disabled", name);
            continue;
        }

        if (!flatpak_remote_get_gpg_verify(rem) && f->gpg_verify) {
            log_warning("remote %s: can't be GPG-verified", name);
            continue;
        }

        if ((uid = remote_resolve_user(name, NULL, 0)) == (uid_t)-1) {
            log_warning("remote %s: no session user", name);
            continue;
        }

        if (f->session_uid != 0 && uid != f->session_uid) {
            log_debug("remote %s: not for session user %d", name, uid);
            continue;
        }

        r = calloc(1, sizeof(*r));

        if (r == NULL)
            goto fail;

        if (!g_hash_table_insert(f->remotes, (void *)name, r))
            goto fail;

        r->r           = g_object_ref(rem);
        r->name        = name;
        r->url         = url;
        r->session_uid = uid;
    }

    g_ptr_array_unref(arr);

    return 0;

 query_failed:
    log_error("flatpak remote query failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    g_ptr_array_unref(arr);
    remote_free(r);

    return -1;
}


void ftpk_forget_remotes(flatpak_t *f)
{
    if (f == NULL)
        return;

    g_hash_table_destroy(f->remotes);
    f->remotes = NULL;
}


remote_t *ftpk_lookup_remote(flatpak_t *f, const char *name)
{
    return f && f->remotes ? g_hash_table_lookup(f->remotes, name) : NULL;
}


static GKeyFile *metadata_load(FlatpakInstalledRef *lref)
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
    bytes = flatpak_installed_ref_load_metadata(lref, NULL, &e);

    if (bytes == NULL)
        goto fail_no_data;

    data = g_bytes_get_data(bytes, &size);

    if (!g_key_file_load_from_data(meta, data, size, 0, &e))
        goto fail_no_data;

    g_bytes_unref(bytes);

    return meta;

 fail_no_data:
    log_error("failed to load flatpak metadata (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    metadata_free(meta);
    g_bytes_unref(bytes);

    return NULL;
}


static void metadata_free(GKeyFile *m)
{
    if (m)
        g_key_file_unref(m);
}


static const char *metadata_get(GKeyFile *m, const char *sec, const char *key)
{
    return m ? g_key_file_get_value(m, sec, key, NULL) : NULL;
}


static GKeyFile *metadata_fetch(flatpak_t *f, FlatpakRemoteRef *rref)
{
    const char *origin;
    FlatpakRef *ref;
    GKeyFile   *meta;
    GBytes     *bytes;
    const void *data;
    size_t      size;
    GError     *e;

    g_object_get(rref, "remote-name", &origin, NULL);

    meta = g_key_file_new();

    if (meta == NULL)
        goto fail;

    e     = NULL;
    ref   = FLATPAK_REF(rref);
    bytes = flatpak_installation_fetch_remote_metadata_sync(f->f, origin, ref,
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
              flatpak_ref_format_ref(ref), origin,
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    ftpk_free_metadata(meta);
    g_bytes_unref(bytes);

    return NULL;
}


static int wants_autostart(GKeyFile *m)
{
    const char *v;

    if (m == NULL)
        return 0;

    v = metadata_get(m, FLATPAK_SECTION_REFKIT, FLATPAK_KEY_START);

    if (v == NULL)
        return 1;

    return !v || !strcasecmp(v, "yes") || !strcasecmp(v, "true");
}


static int wants_autoinstall(GKeyFile *m)
{
    const char *v;

    if (m == NULL)
        return 0;

    v = metadata_get(m, FLATPAK_SECTION_REFKIT, FLATPAK_KEY_INSTALL);

    if (v == NULL)
        return 1;

    return !v || !strcasecmp(v, "yes") || !strcasecmp(v, "true");
}


static const char *wants_urgency(GKeyFile *m)
{
    const char *v;

    if (m == NULL)
        return 0;

    v = metadata_get(m, FLATPAK_SECTION_REFKIT, FLATPAK_KEY_URGENCY);

    return v ? v : "none";
}


int ftpk_discover_apps(flatpak_t *f)
{
    GPtrArray           *arr;
    GError              *e;
    application_t       *a;
    remote_t            *r;
    FlatpakRefKind       knd;
    FlatpakInstalledRef *lref;
    const char          *origin, *name;
    GKeyFile            *meta;
    int                  i;

    if (f->apps != NULL)
        return 0;

    if (ftpk_discover_remotes(f) < 0)
        return -1;

    knd = FLATPAK_REF_KIND_APP;
    e   = NULL;
    arr = flatpak_installation_list_installed_refs_by_kind(f->f, knd, NULL, &e);

    if (arr == NULL)
        goto query_failed;

    for (i = 0; i < (int)arr->len; i++) {
        lref   = g_ptr_array_index(arr, i);
        origin = flatpak_installed_ref_get_origin(lref);
        r      = ftpk_lookup_remote(f, origin);

        if (r == NULL) {
            log_warning("ignoring app without associated remote");
            continue;
        }

        meta = metadata_load(lref);

        if (meta == NULL)
            goto fail;

        name = metadata_get(meta, FLATPAK_SECTION_APP, FLATPAK_KEY_NAME);

        if (name == NULL) {
            log_warning("ignoring app without a name");
            metadata_free(meta);
            continue;
        }

        a = calloc(1, sizeof(*a));

        if (a == NULL)
            goto fail;

        a->lref   = g_object_ref(lref);
        a->origin = origin;
        a->name   = name;
        a->meta   = meta;
        a->start  = wants_autostart(meta);

        if (!g_hash_table_insert(f->apps, (void *)name, a))
            goto fail;
    }

    g_ptr_array_unref(arr);

    return 0;

 query_failed:
    log_error("flatpak application query failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    goto fail;

 fail:
    g_ptr_array_unref(arr);
    app_free(a);

    return -1;
}


int ftpk_discover_updates(flatpak_t *f)
{
    GPtrArray        *arr;
    FlatpakRemoteRef *rref;
    remote_t         *r;
    application_t    *a;
    GKeyFile         *meta;
    const char       *origin, *name;
    GError           *e;
    int               i;

    if (ftpk_init(f) < 0)
        return -1;

    if (ftpk_discover_apps(f) < 0)
        return -1;

    ftpk_foreach_remote(f, r) {
        meta = NULL;
        e    = NULL;
        name = r->name;
        arr  = flatpak_installation_list_remote_refs_sync(f->f, name, NULL, &e);

        if (arr == NULL && e != NULL && e->code != 0)
            goto query_failed;

        r->urgent = 0;

        for (i = 0; i < (int)arr->len; i++) {
            rref   = g_ptr_array_index(arr, i);
            origin = r->name;
            name   = flatpak_ref_get_name(FLATPAK_REF(rref));

            if (flatpak_ref_get_kind(FLATPAK_REF(rref)) != FLATPAK_REF_KIND_APP)
                continue;

            meta = metadata_fetch(f, rref);

            if (meta == NULL) {
                log_warning("ignorning update without metadata");
                continue;
            }

            a = ftpk_lookup_app(f, name);

            if (a == NULL) {
                if (!wants_autoinstall(meta)) {
                    log_warning("app %s/%s: no autoinstall, ignoring...",
                                origin, name);
                    continue;
                }

                a = calloc(1, sizeof(*a));

                if (a == NULL)
                    goto fail;

                if (!g_hash_table_insert(f->apps, (void *)name, a))
                    goto fail;

                a->rref   = g_object_ref(rref);
                a->origin = origin;
                a->name   = name;
                a->meta   = meta;

                log_info("app %s/%s: pending installation", a->origin, a->name);
            }
            else {
                a->urgency = wants_urgency(meta);

                log_info("app %s/%s: pending update (urgency: %s)",
                         a->origin, a->name, a->urgency);

                if (!strcmp(a->urgency, "important") ||
                    !strcmp(a->urgency, "critical"))
                    r->urgent = 1;
            }
        }

        g_ptr_array_unref(arr);
    }

    return 0;

 query_failed:
    log_error("flatpak update query failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    g_ptr_array_unref(arr);
    app_free(a);

    return -1;
}


void ftpk_forget_apps(flatpak_t *f)
{
    if (f == NULL)
        return;

    g_hash_table_destroy(f->apps);
    f->apps = NULL;
}


application_t *ftpk_lookup_app(flatpak_t *f, const char *name)
{
    return f && f->apps ? g_hash_table_lookup(f->apps, name) : NULL;
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
    application_t *a = user_data;

    UNUSED_ARG(estim);

    log_info("%s/%s: %s: %u %%...", a->origin, a->name, status, progress);
}


int ftpk_fetch_updates(flatpak_t *f, application_t *a)
{
    const char          *origin = a->origin;
    const char          *name   = a->name;
    FlatpakRefKind       kind   = FLATPAK_REF_KIND_APP;
    int                  flags  = a->lref ? FLATPAK_UPDATE_FLAGS_NO_DEPLOY : 0;
    GError              *e      = NULL;
    FlatpakInstalledRef *u;

    if (f->dry_run)
        return 0;

    if (a->lref)
        u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                        update_progress_cb, a, NULL, &e);
    else
        u = flatpak_installation_install(f->f, origin, kind, name, NULL, NULL,
                                         update_progress_cb, a, NULL, &e);

    if (u == NULL && e->code != 0)
        goto fetch_failed;

    if (u == NULL || (a->lref != NULL && u == a->lref))
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
              a->origin, a->name,
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_apply_updates(flatpak_t *f, application_t *a)
{
    const char          *name  = a->name;
    FlatpakRefKind       kind  = FLATPAK_REF_KIND_APP;
    int                  flags = FLATPAK_UPDATE_FLAGS_NO_PULL;
    GError              *e     = NULL;
    FlatpakInstalledRef *u;

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, a, NULL, &e);

    if (u == NULL && e->code != 0)
        goto fetch_failed;

    if (u == a->lref || u == NULL)
        return 0;
    else {
        g_object_unref(a->lref);
        a->lref = g_object_ref(u);

        metadata_free(a->meta);
        a->meta = metadata_load(a->lref);

        return 1;
    }

 fetch_failed:
    log_error("failed to fetch updates (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_update_app(flatpak_t *f, application_t *a)
{
    const char          *name  = a->name;
    FlatpakRefKind       kind  = FLATPAK_REF_KIND_APP;
    int                  flags = FLATPAK_UPDATE_FLAGS_NONE;
    GError              *e     = NULL;
    FlatpakInstalledRef *u;

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, a, NULL, &e);

    if (u == NULL && e->code != 0)
        goto update_failed;

    if (u == a->lref || u == NULL)
        return 0;
    else {
        g_object_unref(a->lref);
        a->lref = g_object_ref(u);

        metadata_free(a->meta);
        a->meta = metadata_load(a->lref);

        g_object_unref(a->rref);
        a->rref = NULL;

        return 1;
    }

 update_failed:
    log_error("update failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_launch_app(flatpak_t *f, application_t *a)
{
    GError *e;
    int     status;

    if (f->dry_run)
        return 0;

    e = NULL;
    sigprocmask(SIG_UNBLOCK, &f->watched, NULL);
    if (!flatpak_installation_launch(f->f, a->name, NULL, NULL, NULL, NULL, &e))
        status = -1;
    else
        status = 0;
    sigprocmask(SIG_BLOCK, &f->watched, NULL);

    if (!status)
        return 0;

    log_error("failed to launch application '%s' (%s: %d:%s).", a->name,
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


int ftpk_signal_app(application_t *a, uid_t uid, pid_t session, int sig)
{
    char  tasks[PATH_MAX], scope[PATH_MAX], exe[PATH_MAX], lnk[PATH_MAX];
    char  task[32];
    pid_t pid;
    FILE *fp;
    int   n, status;

    if (session == 0)
        session = getpid();

    n = snprintf(tasks, sizeof(tasks), "%s/tasks",
                 ftpk_scope(uid, session, a->name, scope, sizeof(scope)));

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

        if (strncmp(exe, FLATPAK_NEW_ROOT"/", sizeof(FLATPAK_NEW_ROOT)))
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


int ftpk_stop_app(application_t *a, uid_t uid, pid_t session)
{
    return ftpk_signal_app(a, uid, session, SIGTERM);
}


int ftpk_signal_session(uid_t uid, int sig)
{
    pid_t pid;

    if ((pid = ftpk_session_pid(uid)) == 0)
        return -1;

    return kill(pid, sig);
}
