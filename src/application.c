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
#include "flatpak-session.h"


static application_t *app_register(flatpak_t *f, FlatpakInstalledRef *a)
{
    application_t *app;
    remote_t      *r;
    const char    *origin;
    GBytes        *bytes;
    const void    *data;
    size_t         size;
    GError        *e;

    app    = NULL;
    bytes  = NULL,
    origin = flatpak_installed_ref_get_origin(a);
    r      = remote_lookup(f, origin);

    if (r == NULL)
        goto discard_no_remote;

    if ((app = calloc(1, sizeof(*app))) == NULL)
        goto fail;

    app->app      = a;
    app->origin   = origin;
    app->metadata = g_key_file_new();

    if (app->metadata == NULL)
        goto fail;

    bytes = flatpak_installed_ref_load_metadata(a, NULL, &e);

    if (bytes == NULL)
        goto fail_no_metadata;

    data = g_bytes_get_data(bytes, &size);

    if (!g_key_file_load_from_data(app->metadata, data, size, 0, &e))
        goto fail_no_metadata;

    g_bytes_unref(bytes);
    bytes = NULL;

    app->name = app_metadata_get(app, "Application", "name");

    if (app->name == NULL)
        goto discard_no_name;

    if (!g_hash_table_insert(f->apps, (void *)app->name, app))
        goto fail;

    log_info("discovered application '%s' (from %s)", app->name, app->origin);

    return app;

 discard_no_remote:
    log_warning("ignoring application without tracked remote '%s'", origin);
    goto discard;
 discard_no_name:
    log_warning("ignoring application without a name");
 discard:
    goto fail;

 fail_no_metadata:
    log_error("failed to load application metadata (%s: %d:%s)",
              g_quark_to_string(e->domain), e->code, e->message);
 fail:
    if (app != NULL) {
        g_key_file_unref(app->metadata);
        free(app);
    }
    g_bytes_unref(bytes);
    return NULL;
}


int app_discover(flatpak_t *f)
{
    int i;

    if (f->apps != NULL)
        return 0;

    if (remote_discover(f) < 0)
        goto fail;

    f->apps = g_hash_table_new(g_str_hash, g_str_equal);

    if (f->apps == NULL)
        goto fail;

    if (ftpk_discover_apps(f) < 0)
        goto fail;

    for (i = 0; i < (int)f->f_apps->len; i++)
        app_register(f, g_ptr_array_index(f->f_apps, i));

    return 0;

 fail:
    return -1;
}


int app_fetch_updates(flatpak_t *f, application_t *app)
{
    return ftpk_fetch_updates(f, app);
}


int app_update_cached(flatpak_t *f, application_t *app)
{
    return ftpk_update_cached(f, app);
}


int app_fetch(flatpak_t *f)
{
    application_t  *app;
    GHashTableIter  it;
    int             status;

    status = 0;

    g_hash_table_iter_init(&it, f->apps);
    while (g_hash_table_iter_next(&it, NULL, (void **)&app)) {
        if (ftpk_fetch_updates(f, app) < 0)
            status = -1;
    }

    return status;
}


int app_update(flatpak_t *f)
{
    application_t  *app;
    GHashTableIter  it;
    int             status;

    status = 0;

    g_hash_table_iter_init(&it, f->apps);
    while (g_hash_table_iter_next(&it, NULL, (void **)&app)) {
        if (ftpk_update_cached(f, app) < 0)
            status = -1;
    }

    return status;
}


const char *app_metadata_get(application_t *app, const char *section,
                             const char *key)
{
    return g_key_file_get_value(app->metadata, section, key, NULL);
}
