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

#include "flatpak-session.h"

static void setup_monitor(flatpak_t *f);
static void setup_signals(flatpak_t *f);

static int generate_sessions(flatpak_t *f)
{
    if (remote_discover(f) < 0)
        return -1;

    if (session_enable(f) < 0)
        return -1;

    return 0;
}


static int list_sessions(flatpak_t *f)
{
    if (app_discover(f) < 0)
        return -1;

    session_list(f);

    return 0;
}


static int start_session(flatpak_t *f)
{
    if (f->wait_signal)
        return 0;

    if (app_discover(f) < 0)
        return -1;

    if (session_start(f) < 0)
        return -1;

    return 0;
}


static int stop_session(flatpak_t *f)
{
    if (app_discover(f) < 0)
        return -1;

    if (session_stop(f) < 0)
        return -1;

    return 0;
}


static int signal_session(flatpak_t *f)
{
    if (app_discover(f) < 0)
        return -1;

    if (session_signal(f) < 0)
        return -1;

    return 0;
}


static int fetch_and_update(flatpak_t *f)
{
    remote_t *r;

    if (app_discover(f) < 0)
        return -1;

    if (app_discover_updates(f) < 0)
        return -1;

    if (app_fetch(f) < 0)
        return -1;

    if (app_update(f) < 0)
        return -1;

    if (f->send_signal != 0) {
        ftpk_foreach_remote(f, r) {
            f->session_uid = r->session_uid;
            session_signal(f);
        }
        f->send_signal = 0;
    }

    return 0;
}


static void sighandler(flatpak_t *f, int signum)
{
    log_info("received signal %d (%s)", signum, strsignal(signum));

    if (f->command == COMMAND_START) {
        if (signum == f->wait_signal) {
            f->wait_signal = 0;
            start_session(f);
            return;
        }
        else {
            f->send_signal = signum;
            signal_session(f);
        }
    }

    switch (signum) {
        case SIGHUP:
            if (f->restart_status != 0)
                exit(f->restart_status);
            break;

        case SIGINT:
            mainloop_quit(f, 0);
            break;

        case SIGTERM:
            mainloop_quit(f, 0);
            break;

    case SIGURG:
        if (f->command == COMMAND_UPDATE)
            fetch_and_update(f);
        break;

    default:
        break;
    }
}


static void setup_signals(flatpak_t *f)
{
    sigemptyset(&f->watched);
    sigaddset(&f->watched, SIGHUP);
    sigaddset(&f->watched, SIGINT);
    sigaddset(&f->watched, SIGQUIT);
    sigaddset(&f->watched, SIGTERM);
    sigaddset(&f->watched, SIGURG);
    if (f->wait_signal)
        sigaddset(&f->watched, f->wait_signal);

    mainloop_watch_signals(f, &f->watched, sighandler);
}


static void monitor_cb(flatpak_t *f)
{
    if (f->updating)
        return;

    f->updating = 1;
    fetch_and_update(f);
    f->updating = 0;
}


static void setup_monitor(flatpak_t *f)
{
    if (f->poll_interval > 0)
        mainloop_enable_monitor(f, monitor_cb);
}


int main(int argc, char **argv)
{
    flatpak_t f;

    config_parse_cmdline(&f, argc, argv);

    if (mainloop_needed(&f))
        mainloop_create(&f);

    switch (f.command) {
    case COMMAND_GENERATE: generate_sessions(&f); break;
    case COMMAND_LIST:     list_sessions(&f);     break;
    case COMMAND_START:    start_session(&f);     break;
    case COMMAND_STOP:     stop_session(&f);      break;
    case COMMAND_SIGNAL:   signal_session(&f);    break;
    case COMMAND_UPDATE:   fetch_and_update(&f);  break;
    default:
        log_error("internal error: unknown command");
        exit(1);
    }

    if (mainloop_needed(&f)) {
        setup_signals(&f);
        setup_monitor(&f);
        mainloop_run(&f);
    }

    return f.exit_code;
}
