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

#include "flatpak-session.h"


static void app_free(gpointer data)
{
    application_t *a = data;

    if (a == NULL)
        return;

    g_object_unref(a->ref);
    g_object_unref(a->upd);
    ftpk_free_metadata(a->metadata);
    free(a);
}


static int app_cb(flatpak_t *f, FlatpakInstalledRef *a, const char *name,
                  const char *origin, GKeyFile *meta)
{
    remote_t      *r;
    application_t *app;

    r = remote_lookup(f, origin);

    if (r == NULL) {
        log_warning("app %s: no associated remote, ignoring...", name);
        return 0;
    }

    if ((app = calloc(1, sizeof(*app))) == NULL)
        return -1;

    app->ref      = g_object_ref(a);
    app->origin   = origin;
    app->name     = name;
    app->metadata = ftpk_ref_metadata(meta);

    if (!g_hash_table_insert(f->apps, (void *)name, app)) {
        app_free(app);
        return -1;
    }

    log_info("discovered application %s/%s", app->origin, app->name);

    return 0;
}


static int update_cb(flatpak_t *f, FlatpakRemoteRef *ref, const char *name,
                     const char *origin, GKeyFile *meta)
{
    application_t *a;
    const char    *install, *ahead, *uhead;

    if (remote_lookup(f, origin) == NULL) {
        log_warning("update %s/%s: no associated remote, ignoring...",
                    origin, name);
        return 0;
    }

    a = app_lookup(f, name);

    if (a == NULL) {
        install = ftpk_get_metadata(meta, "Application", "install");

        if (install == NULL && !(install[0] == 'y' || install[0] == 't')) {
            log_warning("application %s/%s: no autoinstall, ignoring...",
                        origin, name);
            return 0;
        }

        a = calloc(1, sizeof(*a));

        if (a == NULL)
            return -1;

        a->origin   = origin;
        a->name     = name;
        a->metadata = ftpk_ref_metadata(meta);
    }
    else {
        uhead = flatpak_ref_get_commit(FLATPAK_REF(ref));
        ahead = flatpak_ref_get_commit(FLATPAK_REF(a->ref));

        if (uhead != NULL && ahead != NULL && !strcmp(uhead, ahead)) {
            log_warning("application %s/%s: already up to date", origin, name);
            return 0;
        }
    }

    a->upd = g_object_ref(ref);

    if (a->ref == NULL) {
        if (!g_hash_table_insert(f->apps, (void *)name, a)) {
            app_free(a);
            return -1;
        }
    }

    log_info("discovered %s %s/%s",
             a->ref ? "pending update for" : "pending installation of",
             origin, name);

    return 1;
}


int app_discover(flatpak_t *f)
{
    if (f->apps != NULL)
        return 0;

    if (remote_discover(f) < 0)
        return -1;

    f->apps = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, app_free);

    if (f->apps == NULL)
        return -1;

    if (ftpk_discover_apps(f, app_cb) < 0)
        return -1;

    return 0;
}


int app_discover_updates(flatpak_t *f)
{
    remote_t *r;
    int       status;

    if (remote_discover(f) < 0)
        return -1;

    status = 0;
    foreach_remote(f, r) {
        if (ftpk_discover_updates(f, r->name, update_cb) < 0)
            status = -1;
    }

    return status;
}


void app_forget(flatpak_t *f)
{
    g_hash_table_destroy(f->apps);
    f->apps    = NULL;
}


application_t *app_lookup(flatpak_t *f, const char *name)
{
    return f && f->apps ? g_hash_table_lookup(f->apps, name) : NULL;
}


int app_fetch(flatpak_t *f)
{
    application_t *app;
    int            status;

    status = 0;

    foreach_app(f, app) {
        if (app->upd == NULL)
            continue;
        if (app->ref != NULL)
            log_info("fetching updates for application %s/%s...",
                     app->origin, app->name);
        else
            log_info("installing application %s/%s...", app->origin, app->name);

        switch (ftpk_fetch_updates(f, app)) {
        case 0:  log_info("no pending updates"); break;
        case 1:  log_info("updates fetched");    break;
        default: status = -1;                    break;
        }
    }

    return status;
}


int app_update(flatpak_t *f)
{
    application_t *app;
    int            status;

    status = 0;

    foreach_app(f, app) {
        log_info("applying updates for application %s/%s...",
                 app->origin, app->name);

        switch (ftpk_apply_updates(f, app)) {
        case 0:  log_info("no updates"); break;
        case 1:  log_info("updated");    break;
        default: status = -1;            break;
        }
    }

    return status;
}
