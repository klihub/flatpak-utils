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
    log_info("generating flatpak sessions...");

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
    log_info("starting flatpak session for user %d", geteuid());

    if (app_discover(f) < 0)
        return -1;

    if (session_start(f) < 0)
        return -1;

    return 0;
}


static int stop_session(flatpak_t *f)
{
    session_stop(f);

    return 0;
}


static int signal_session(flatpak_t *f)
{
    ftpk_signal_session(f->uid, f->sig);

    return 0;
}


static int fetch_updates(flatpak_t *f)
{
    log_info("fetching updates...");

    if (app_discover(f) < 0)
        return -1;

    if (app_fetch(f) < 0)
        return -1;

    return 0;
}


static int update_cached(flatpak_t *f)
{
    log_info("applying cached updates...");

    if (app_discover(f) < 0)
        return -1;

    if (app_update(f) < 0)
        return -1;

    return 0;
}


static int fetch_and_update(flatpak_t *f)
{
    log_info("fetching updates and updating applications...");

    if (app_discover(f) < 0)
        return -1;

    if (app_fetch(f) < 0)
        return -1;

    if (app_update(f) < 0)
        return -1;

    return 0;
}


static void sighandler(flatpak_t *f, int signum)
{
    /*
    if (f->command == COMMAND_START) {
        f->sig = signum;
        session_signal(f);
        }
    */

    switch (signum) {
    case SIGHUP:
        log_info("received SIGHUP");
        if (f->command == COMMAND_START)
            exit(f->restart_status);
        break;
    case SIGINT:
        log_info("received SIGINT");
        mainloop_quit(f, 0);
        break;
    case SIGTERM:
        log_info("received SIGTERM");
        mainloop_quit(f, 0);
        break;
    case SIGURG:
        log_info("received SIGURG");
        switch (f->command) {
        case COMMAND_FETCH:
            fetch_updates(f);
            break;
        case COMMAND_UPDATE:
            fetch_and_update(f);
            break;
        default:
            break;
        }
    default:
        break;
    }
}


static void setup_signals(flatpak_t *f)
{
    sigemptyset(&f->blocked);
    sigaddset(&f->blocked, SIGHUP);
    sigaddset(&f->blocked, SIGINT);
    sigaddset(&f->blocked, SIGQUIT);
    sigaddset(&f->blocked, SIGTERM);
    sigaddset(&f->blocked, SIGURG);

    mainloop_watch_signals(f, &f->blocked, sighandler);
}


static void monitor_cb(flatpak_t *f)
{
    if (f->updating)
        return;

    f->updating = 1;

    switch (f->command) {
    case COMMAND_FETCH:  fetch_updates(f);     break;
    case COMMAND_APPLY:  update_cached(f);     break;
    case COMMAND_UPDATE: fetch_and_update(f);  break;
    default:
        break;
    }

    f->updating = 0;
}


static void setup_monitor(flatpak_t *f)
{
    mainloop_enable_monitor(f, monitor_cb);
}


static inline int needs_mainloop(flatpak_t *f)
{
    return (f->poll_interval > 0 ||
            f->command == COMMAND_START || f->command == COMMAND_STOP);
}


int main(int argc, char **argv)
{
    flatpak_t f;

    config_parse_cmdline(&f, argc, argv);

    if (needs_mainloop(&f))
        mainloop_create(&f);

    switch (f.command) {
    case COMMAND_GENERATE: generate_sessions(&f); break;
    case COMMAND_LIST:     list_sessions(&f);     break;
    case COMMAND_START:    start_session(&f);     break;
    case COMMAND_STOP:     stop_session(&f);      break;
    case COMMAND_SIGNAL:   signal_session(&f);    break;
    case COMMAND_FETCH:    fetch_updates(&f);     break;
    case COMMAND_APPLY:    update_cached(&f);     break;
    case COMMAND_UPDATE:   fetch_and_update(&f);  break;
    default:
        log_error("unknown command");
        exit(1);
    }

    if (needs_mainloop(&f)) {
        setup_signals(&f);

        if (f.command != COMMAND_START)
            setup_monitor(&f);

        mainloop_run(&f);
    }

    return f.exit_code;
}
