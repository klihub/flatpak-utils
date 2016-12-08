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


static void metadata_free(GKeyFile *m)
{
    if (m != NULL)
        g_key_file_unref(m);
}


static GKeyFile *metadata_load(FlatpakInstalledRef *ref)
{
    GKeyFile   *m;
    GBytes     *b;
    const void *d;
    size_t      l;
    GError     *e;

    m = g_key_file_new();

    if (m == NULL)
        goto fail;

    e = NULL;
    b = flatpak_installed_ref_load_metadata(ref, NULL, &e);

    if (b == NULL)
        goto fail_no_data;

    d = g_bytes_get_data(b, &l);

    if (d == NULL)
        goto fail_no_data;

    d = g_bytes_get_data(b, &l);

    if (!g_key_file_load_from_data(m, d, l, 0, &e))
        goto fail_no_data;

    g_bytes_unref(b);

    return m;

 fail_no_data:
    log_error("flatpak: failed to load metadata (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    metadata_free(m);
    g_bytes_unref(b);

    return NULL;
}


static GKeyFile *metadata_fetch(flatpak_t *f, FlatpakRemoteRef *rref)
{
    GKeyFile   *m;
    GBytes     *b;
    const void *d;
    size_t      l;
    FlatpakRef *ref;
    const char *remote;
    GError     *e;

    m = g_key_file_new();

    if (m == NULL)
        goto fail;

    g_object_get(rref, "remote-name", &remote, NULL);

    ref = FLATPAK_REF(rref);
    e   = NULL;
    b   = flatpak_installation_fetch_remote_metadata_sync(f->f, remote, ref,
                                                          NULL &e);

    if (b == NULL)
        goto fail_no_data;

    d = g_bytes_get_data(b, &l);

    if (!g_key_file_load_from_data(m, d, l, 0, &e))
        goto fail_no_data;

    g_bytes_unref(b);

    return m;

 fail_no_data:
    log_error("flatpak: failed to fetch metadata (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    metadata_free(m);
    g_bytes_unref(b);

    return NULL;
}


static const char *metadata_get(GKeyFile *m, const char *sec, const char *key,
                                const char *def)
{
    const char *val;

    if (m == NULL)
        val = def;
    else
        val = g_key_file_get_value(m, sec, key, NULL);

    return val ? val : def;
}


#define metadata_string metadata_get


static int metadata_bool(GKeyFile *m, const char *sec, const char *key, int def)
{
    const char *val = metadata_get(m, sec, key, NULL);

    if (val == NULL)
        return def;

    if (!strcasecmp(val, "true") || !strcasecmp(val, "yes") || !strcmp(val, "1"))
        return 1;
    else
        return 0;
}


static int get_autoinstall(GKeyFile *m)
{
    return metadata_bool(m, FLATPAK_SECTION_APP, FLATPAK_KEY_INSTALL, 1);
}


static int get_autostart(GKeyFile *m)
{
    return metadata_bool(m, FLATPAK_SECTION_APP, FLATPAK_KEY_START, 1);
}


static int get_urgency(GKeyFile *m)
{
    const char *urgency;

    metadata_get(m, FLATPAK_SECTION_APP, FLATPAK_KEY_URGENCY, "none");

    if (!strcasecmp(urgency, "critical"))
        return 1;
    if (!strcasecmp(urgency, "important"))
        return 1;
    else
        return 0;
}


static void remote_free(gpointer ptr)
{
    remote_t *r = ptr;

    if (r == NULL)
        return;

    if (r->ref)
        g_object_unref(r->ref);

    free(r);
}


static void app_free(gpointer ptr)
{
    application_t *a = ptr;

    if (a == NULL)
        return;

    if (a->ref)
        g_object_unref(a->ref);

    free(a->commit);
    free(a->origin);
    free(a->name);

    free(a);
}


static int ftpk_init(flatpak_t *f)
{
    GError *e = NULL;

    if (f->f != NULL)
        return 0;

    if ((f->f = flatpak_installation_new_system(NULL, &e)) != NULL)
        return 0;

    log_error("flatpak: failed to initialize library (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


void ftpk_reset(flatpak_t *f)
{
    GError *e;

    ftpk_clear_remotes(f);
    ftpk_clear_apps(f);

    e = NULL;
    flatpak_installation_drop_caches(f->f, NULL, &e);
}


void ftpk_exit(flatpak_t *f)
{
    ftpk_reset(f);
    if (f->f) {
        g_object_unref(f->f);
        f->f = NULL;
    }
}


int ftpk_discover_remotes(flatpak_t *f)
{
    GPtrArray     *refs;
    GError        *e;
    remote_t      *r;
    FlatpakRemote *ref;
    const char    *name, *url;
    uid_t          uid;
    int            i;

    if (f->remotes != NULL)
        return 0;

    if (ftpk_init(f) < 0)
        return -1;

    f->remotes = g_hash_table_new_full(g_str_hash, g_str_equal,
                                       NULL, remote_free);

    if (f->remotes == NULL)
        return -1;

    r    = NULL;
    e    = NULL;
    refs = flatpak_installation_list_remotes(f->f, NULL, &e);

    if (refs == NULL)
        goto query_failed;

    for (i = 0; i < (int)refs->len; i++) {
        ref  = g_ptr_array_index(refs, i);
        name = flatpak_remote_get_name(ref);
        url  = flatpak_remote_get_url(ref);

        if (flatpak_remote_get_disabled(ref)) {
            log_warning("remote %s: disabled", name);
            continue;
        }

        if (!flatpak_remote_get_gpg_verify(rem) && f->gpg_verify) {
            log_warning("remote %s: can't be GPG-verified, disabled", name);
            continue;
        }

        if ((uid = remote_resolve_user(name, NULL, 0)) == (uid_t)-1) {
            log_warning("remote %s: no associated user, disabled", name);
            continue;
        }

        if (f->session_uid != 0 && uid != f->session_uid) {
            log_debug("remote %s: for other session, skipped", name, uid);
            continue;
        }

        r = calloc(1, sizeof(*r));

        if (r == NULL)
            goto fail;

        r->ref         = g_object_ref(ref);
        r->name        = name;
        r->url         = url;
        r->session_uid = uid;

        if (!g_hash_table_insert(f->remotes, (void *)name, r))
            goto fail;
    }

    g_ptr_array_unref(refs);

    return 0;

 query_failed:
    log_error("flatpak: failed to query remotes (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    remote_free(r);
    g_ptr_array_unref(refs);
    ftpk_clear_remotes(f);

    return -1;
}


void ftpk_clear_remotes(flatpak_t *f)
{
    g_hash_table_destroy(f->remotes);
    f->remotes = NULL;
}


remote_t *ftpk_lookup_remote(flatpak_t *f, const char *name)
{
    return f->remotes ? g_hash_table_lookup(f->remotes, name) : NULL;
}


int ftpk_discover_apps(flatpak_t *f)
{
    remote_t            *r;
    application_t       *a;
    FlatpakInstalledRef *ref;
    FlatpakRefKind       knd;
    const char          *origin, *name;
    GKeyFile            *m;
    GPtrArray           *refs;
    GError              *e;
    int                  start, i;

    if (f->apps != NULL)
        return 0;

    if (ftpk_discover_remotes(f) < 0)
        return -1;

    f->apps = g_hash_table_new_full(g_str_hash, g_str_equal,
                                    NULL, app_free);

    if (f->apps == NULL)
        return -1;

    e    = NULL;
    knd  = FLATPAK_REF_KIND_APP;
    refs = flatpak_installation_list_installed_refs_by_kind(f->f, knd, NULL, &e);

    if (refs == NULL)
        goto query_failed;

    for (i = 0; i < (int)refs->len; i++) {
        ref    = g_ptr_array_index(refs, i);
        origin = flatpak_installed_ref_get_origin(ref);
        name   = flatpak_ref_get_name(FLATPAK_REF(ref));

        if ((r = ftpk_lookup_remote(f, origin)) == NULL) {
            log_debug("app %s: no remote, ignored", name);
            continue;
        }

        if ((m = metadata_load(ref)) == NULL)
            goto metadata_failed;
        start = get_autostart(m);
        metadata_free(m);

        if (!start) {
            log_warning("app %s/%s: not autostarted, skipping", origin, name);
            continue;
        }

        a = calloc(1, sizeof(*a));

        if (a == NULL)
            goto fail;

        a->ref    = g_object_ref(ref);
        a->origin = strdup(origin);
        a->name   = strdup(name);
        a->commit = strdup(flatpak_ref_get_commit(FLATPAK_REF(ref));

        if (a->origin == NULL || a->name == NULL || a->commit == NULL)
            goto fail;

        if (!g_hash_table_insert(f->apps, (void *)a->name, a))
            goto fail;
    }

    g_ptr_array_unref(refs);

    return 0;

 query_failed:
    log_error("flatpak: application query failed (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
    goto fail;
 metadata_failed:
    log_error("flatpak: failed to load metadata for %s/%s", origin, name);
 fail:
    app_free(a);
    g_ptr_array_unref(refs);
    ftpk_clear_apps(f);

    return -1;
}


int ftpk_discover_updates(flatpak_t *f)
{
    remote_t         *r;
    application_t    *a;
    FlatpakRemoteRef *ref;
    const char       *origin, *name;
    GKeyFile         *m;
    GPtrArray        *refs;
    GError           *e;
    int               install, start, urgent, i;

    if (ftpk_init(f) < 0)
        return -1;

    if (ftpk_discover_apps(f) < 0)
        return -1;

    ftpk_foreach_remote(f, r) {
        m      = NULL;
        e      = NULL;
        origin = name = r->name;

        refs = flatpak_installation_list_remote_refs_sync(f->f, name, NULL, &e);

        if (refs == NULL)
            goto query_failed;

        for (i = 0; i < (int)refs->len; i++) {
            ref  = g_ptr_array_index(arr, i);
            name = flatpak_ref_get_name(FLATPAK_REF(ref));

            if (flatpak_ref_get_kind(FLATPAK_REF(ref)) != FLATPAK_REF_KIND_APP)
                continue;

            if ((m = metadata_fetch(f, ref)) == NULL) {
                log_warning("flatpak: failed to fetch metadata for %s/%s",
                            origin, name);
                continue;
            }

            install = get_autoinstall(m);
            start   = get_autostart(m);
            urgent  = get_urgency(m);

            metadata_free(m);

            a = ftpk_lookup_app(f, name);

            if (a != NULL) {
                a->updates = 1;
                a->urgent  = urgent;
            }
            else {
                if (!install) {
                    log_warning("app %s/%s: not autoinstalled, skipping",
                                origin, name);
                    continue;
                }

                a = calloc(1, sizeof(*a));

                if (a == NULL)
                    goto fail;

                a->ref   =  g_object_ref(rref);
                a->origin = strdup(origin);
                a->name   = strdup(name);

                if (a->origin == NULL || a->name == NULL)
                    goto fail;

                if (!g_hash_table_insert(f->apps, (void *)a->name, a))
                    goto fail;
            }
            else {
                a->updates = 1;
                a->urgent  = urgent;
            }
        }

        g_ptr_array_unref(refs);
    }

    return 0;

 query_failed:
    log_error("flatpak: failed to query updates (%s: %d: %s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    app_free(a);
    g_ptr_array_unref(refs);

    return -1;
}


void ftpk_clear_apps(flatpak_t *f)
{
    g_hash_table_destroy(f->apps);
    f->apps = NULL;
}


application_t *ftpk_lookup_app(flatpak_t *f, const char *name)
{
    return f && f->apps ? g_hash_table_lookup(f->apps, name) : NULL;
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
        if (a->lref)
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
        if (a->lref)
            g_object_unref(a->lref);
        a->lref = g_object_ref(u);

        metadata_free(a->meta);
        a->meta = metadata_load(a->lref);

        if (a->rref)
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
