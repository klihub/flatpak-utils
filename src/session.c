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

#include "flatpak-session.h"


static int session_link(flatpak_t *f, remote_t *r)
{
    const char *usr = remote_username(r, NULL, 0);
    char        srv[PATH_MAX], lnk[PATH_MAX];

    if (!fsys_service_path(f, usr, srv, sizeof(srv)) ||
        !fsys_service_link(f, usr, lnk, sizeof(lnk)))
        return -1;

    log_info("linking session template %s to %s...", srv, lnk);

    if (!f->dry_run) {
        unlink(lnk);

        if (symlink(srv, lnk) < 0)
            return -1;
    }

    return 0;
}


int session_enable(flatpak_t *f)
{
    GHashTableIter  it;
    remote_t       *r;
    int             status;

    if (fsys_prepare_sessions(f) < 0)
        return -1;

    status = 0;

    g_hash_table_iter_init(&it, f->remotes);
    while (g_hash_table_iter_next(&it, NULL, (void **)&r)) {
        if (session_link(f, r) < 0)
            status = -1;
    }

    return status;
}


int session_start(flatpak_t *f)
{
    remote_t       *r = remote_for_user(f, geteuid());
    application_t  *app;
    GHashTableIter  it;

    g_hash_table_iter_init(&it, f->apps);
    while (g_hash_table_iter_next(&it, NULL, (void **)&app)) {
        if (remote_lookup(f, app->origin) == r)
            ftpk_launch_app(f, app);
    }

    return 0;
}


int session_stop(flatpak_t *f)
{
    UNUSED_ARG(f);

    return 0;
}
