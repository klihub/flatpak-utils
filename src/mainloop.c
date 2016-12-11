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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "flatpak-session.h"


int mainloop_needed(flatpak_t *f)
{
    switch (f->command) {
    case COMMAND_UPDATE:
        return f->poll_interval > 0;
    case COMMAND_START:
    case COMMAND_STOP:
        return TRUE;
    default:
        return FALSE;
    }
}


void mainloop_create(flatpak_t *f)
{
    if (f->loop != NULL)
        return;

    f->loop = g_main_loop_new(NULL, FALSE);

    if (f->loop != NULL)
        return;

    log_error("failed to create mainloop.");
    exit(1);
}


void mainloop_run(flatpak_t *f)
{
    g_main_loop_run(f->loop);
}


void mainloop_quit(flatpak_t *f, int exit_code)
{
    if (!f->exit_code && exit_code)
        f->exit_code = exit_code;

    g_main_loop_quit(f->loop);
}


void mainloop_destroy(flatpak_t *f)
{
    mainloop_ditch_signals(f);
    mainloop_disable_monitor(f);
    g_main_loop_unref(f->loop);
    f->loop = NULL;
}


static gboolean sigevent(GIOChannel *gio, GIOCondition event, gpointer data)
{
    flatpak_t               *f = data;
    struct signalfd_siginfo  si;
    int                      sig;

    UNUSED_ARG(gio);

    if (event & G_IO_IN) {
        while (read(f->sfd, &si, sizeof(si)) > 0) {
            sig = si.ssi_signo;
            log_info("received signal %d (%s)", sig, strsignal(sig));

            f->sighandler(f, sig);
        }
    }

    return G_SOURCE_CONTINUE;
}


int mainloop_watch_signals(flatpak_t *f, sigset_t *ss,
                           void (*h)(flatpak_t *, int))
{
    sigprocmask(SIG_BLOCK, ss, NULL);

    if (h != NULL) {
        if (f->sighandler == NULL)
            f->sighandler = h;
        else
            goto alreadyset;
    }

    f->sfd = signalfd(f->sfd, ss, SFD_NONBLOCK | SFD_CLOEXEC);
    f->sio = g_io_channel_unix_new(f->sfd);

    if (f->sio == NULL)
        goto fail;

    f->sid = g_io_add_watch(f->sio, G_IO_IN, sigevent, f);

    return 0;

 alreadyset:
    errno = EBUSY;
 fail:
    return -1;
}


void mainloop_ditch_signals(flatpak_t *f)
{
    g_source_remove(f->sid);
    g_io_channel_unref(f->sio);
    close(f->sfd);

    f->sio        = NULL;
    f->sid        = 0;
    f->sfd        = -1;
    f->sighandler = NULL;
}


static gboolean monitor_timer(gpointer data)
{
    flatpak_t *f = data;

    f->monitor(f);

    return G_SOURCE_CONTINUE;
}


int mainloop_enable_monitor(flatpak_t *f, void (*cb)(flatpak_t *))
{
    if (f->monitor != NULL)
        goto alreadyset;

    f->monitor = cb;
    f->mid     = g_timeout_add(f->poll_interval * 1000, monitor_timer, f);

    if (f->mid == 0)
        goto fail;

    return 0;

 alreadyset:
    errno = EBUSY;
 fail:
    return -1;
}


void mainloop_disable_monitor(flatpak_t *f)
{
    if (f->mid)
        g_source_remove(f->mid);

    f->mid     = 0;
    f->monitor = NULL;
}


unsigned int mainloop_add_timer(flatpak_t *f, int msec, int (*cb)(void *))
{
    return g_timeout_add(msec, cb, f);
}


void mainloop_del_timer(flatpak_t *f, unsigned int id)
{
    UNUSED_ARG(f);

    if (id > 0)
        g_source_remove(id);
}
