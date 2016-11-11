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

    log_error("failed to initialize flatpak (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


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


int ftpk_load_metadata(application_t *app, int reload)
{
    GBytes     *bytes;
    const void *data;
    size_t      size;
    const char *start;
    GError     *e;

    if (app->metadata != NULL && !reload)
        return 0;

    bytes = NULL;

    if (app->metadata != NULL)
        g_key_file_unref(app->metadata);
    app->metadata = g_key_file_new();

    if (app->metadata == NULL)
        goto fail;

    e     = NULL;
    bytes = flatpak_installed_ref_load_metadata(app->app, NULL, &e);

    if (bytes == NULL)
        goto fail_no_metadata;

    data = g_bytes_get_data(bytes, &size);

    if (!g_key_file_load_from_data(app->metadata, data, size, 0, &e))
        goto fail_no_metadata;

    g_bytes_unref(bytes);

    app->name    = ftpk_get_metadata(app, "Application", "name");
    app->urgency = ftpk_get_metadata(app, "Application", "urgency");
    start        = ftpk_get_metadata(app, "Application", "autostart");

    if (start && (!strcasecmp(start, "true") || !strcasecmp(start, "yes")))
        app->autostart = 1;

    return 0;

 fail_no_metadata:
    log_error("failed to load application metadata (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    if (app != NULL) {
        if (app->metadata != NULL)
            g_key_file_unref(app->metadata);
        free(app);
    }
    g_bytes_unref(bytes);
    return -1;
}


const char *ftpk_get_metadata(application_t *app, const char *section,
                              const char *key)
{
    ftpk_load_metadata(app, 0);

    return g_key_file_get_value(app->metadata, section, key, NULL);
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

    if (u == app->app || (u == NULL && e->code == 0))
        log_info("no pending updates");
    else if (u != NULL) {
        ftpk_load_metadata(app, TRUE);
        log_info("pending updates fetched (urgency: %s, start: %s)",
                 app->urgency ? app->urgency : "<unknown>",
                 app->autostart ? "yes" : "no");
    }
    else
        goto fetch_failed;

    return 0;

 fetch_failed:
    log_error("failed to fetch updates (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


int ftpk_update_cached(flatpak_t *f, application_t *app)
{
    const char          *origin = app->origin;
    const char          *name   = app->name;
    FlatpakRefKind       kind   = FLATPAK_REF_KIND_APP;
    int                  flags  = FLATPAK_UPDATE_FLAGS_NO_PULL;
    GError              *e      = NULL;
    FlatpakInstalledRef *u;

    log_info("applying cached updates to application %s/%s...", origin, name);

    if (f->dry_run)
        return 0;

    u = flatpak_installation_update(f->f, flags, kind, name, NULL, NULL,
                                    update_progress_cb, app, NULL, &e);

    if (u == app->app || (u == NULL && e->code == 0))
        log_info("%s/%s is already up-to-date", app->origin, name);
    else if (u != NULL) {
        ftpk_load_metadata(app, TRUE);
        log_info("%s/%s updated", app->origin, name);
    }
    else
        goto update_failed;

    return 0;

 update_failed:
    log_error("update failed (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
    return -1;
}


static char *ftpk_scope(uid_t uid, pid_t session, const char *app,
                        char *buf, size_t size)
{
    int n;

    if (uid == (uid_t)-1)
        uid = geteuid();
    if (session == (pid_t)-1)
        session = getpid();

    n = snprintf(buf, size,
                 "%s/user-%u.slice/user@%u.service/flatpak-%s-%u.scope",
                 SYSTEMD_USER_SLICE, uid, uid, app, session);

    if (n < 0 || n >= (int)size)
        return NULL;

    return buf;
}


int ftpk_launch_app(flatpak_t *f, application_t *app)
{
    GError *e;

    log_info("launching application %s/%s...", app->origin, app->name);

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


int ftpk_signal_app(flatpak_t *f, application_t *app, uid_t uid, pid_t session,
                    int sig)
{
    char  tasks[PATH_MAX], scope[PATH_MAX], exe[PATH_MAX], lnk[PATH_MAX];
    char  task[32], *base;
    pid_t pid;
    FILE *fp;
    int   n, status;

    UNUSED_ARG(f);

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

        if (readlink(lnk, exe, sizeof(exe)) < 0)
            continue;

        if ((base = strrchr(exe, '/')) != NULL)
            base++;
        else
            base = exe;

        if (!strcmp(base, FLATPAK_BWRAP))
            continue;

        log_info("Sending process %u (%s) signal %d (%s)...",
                 pid, exe, sig, strsignal(sig));

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
