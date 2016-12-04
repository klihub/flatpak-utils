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

#include <string.h>

#include "flatpak-session.h"


static int session_link(flatpak_t *f, remote_t *r)
{
    const char *usr = remote_username(r, NULL, 0);
    char        srv[PATH_MAX], lnk[PATH_MAX];

    if (!fsys_service_path(f, usr, srv, sizeof(srv)) ||
        !fsys_service_link(f, usr, lnk, sizeof(lnk)))
        return -1;

    if (!f->dry_run) {
        unlink(lnk);

        log_info("linking %s to %s...", srv, lnk);

        if (symlink(srv, lnk) < 0)
            return -1;
    }

    return 0;
}


int session_enable(flatpak_t *f)
{
    remote_t *r;
    int       status;

    log_info("generating flatpak application sessions...");

    if (fsys_prepare_session(f) < 0)
        return -1;

    status = 0;

    ftpk_foreach_remote(f, r) {
        log_info("setting up session for remote %s...", r->name);

        if (session_link(f, r) < 0)
            status = -1;
    }

    return status;
}


int session_list(flatpak_t *f)
{
    remote_t      *r;
    application_t *a;
    const char    *usr;

    ftpk_foreach_remote(f, r) {
        usr = remote_username(r, NULL, 0);

        printf("remote %s (%s, user %d (%s)):\n", r->name, r->url,
               r->session_uid, usr);

        ftpk_foreach_app(f, a) {
            if (!strcmp(a->origin, r->name))
                printf("    application %s\n", a->name);
        }
    }

    return 0;
}


int session_start(flatpak_t *f)
{
    remote_t      *r = remote_for_user(f, f->session_uid);
    application_t *a;

    if (r == NULL)
        return 0;

    log_info("starting flatpak session for remote %s (uid %d)",
             r->name, r->session_uid);

    ftpk_foreach_app(f, a) {
        if (!a->start)
            continue;

        log_info("launching application %s/%s", a->origin, a->name);

        if (!f->dry_run)
            ftpk_launch_app(f, a);
    }

    return 0;
}


int session_stop(flatpak_t *f)
{
    pid_t session;

    log_info("stopping session for remote %d...", f->session_uid);

    if (f->dry_run)
        return 0;

    if (!(session = ftpk_session_pid(f->session_uid)))
        return 0;

    kill(session, f->send_signal ? f->send_signal : SIGTERM);

    return 0;
}


int session_signal(flatpak_t *f)
{
    uid_t           uid = f->session_uid;
    remote_t       *r   = remote_for_user(f, uid);
    int             sig = f->send_signal;
    application_t  *app;
    int             status;

    if (f->command == COMMAND_SIGNAL) {
        log_info("sending session of %d signal #%d", uid, sig);

        if (f->dry_run)
            return 0;
        else
            return ftpk_signal_session(uid, sig);
    }


    log_info("sending applications signal #%d", sig);

    status = 0;
    ftpk_foreach_app(f, app) {
        if (remote_lookup(f, app->origin) != r)
            continue;

        log_info("signalling application %s...", app->name);

        if (!f->dry_run)
            if (ftpk_signal_app(app, uid, getpid(), sig) < 0)
                status = -1;
    }

    return status;
}
