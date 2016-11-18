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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "flatpak-session.h"

static void print_usage(const char *argv0, int exit_code, const char *fmt, ...)
{
    va_list ap;

    if (fmt && *fmt) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }

    fprintf(stderr, "usage: %s [options] {enable|update [options] [remotes]}\n"
            "\n"
            "The command enable will enable all or just the specified\n"
            "flatpak sessions. The command update the applications for all\n"
            "or just the selected remote.\n"
            "\n"
            "The possible common options are:\n"
            "  -u, --allow-unsigned      allow unverifiable (unsigned) remotes\n"
            "  -n, --dry-run             just print, don't generate anything\n"
            "  -v, --verbose             increase logging verbosity\n"
            "  -h, --help                print this help message\n"
            "\n"
            "The possible options for start are:\n"
            "  -r, --restart-status <n>  use n for forced restart exit status\n"
            "\n"
            "The possible options for update are:\n"
            "  -f, --fetch               just fetch, don't update\n"
            "  -l, --local               update locally from fetched changes\n"
            "  -m, --monitor             daemonize and poll/fetch updates\n"
            "  -i, --poll-interval ival  use the given interval for polling\n",
            argv0);

    if (exit_code < 0)
        return;
    else
        exit(exit_code);
}


static inline int is_systemd_generator(const char *argv0)
{
    const char *p;

    if ((p = strrchr(argv0, '/')) == NULL)
        p = argv0;
    else
        p++;

    return !strcmp(p, SYSTEMD_GENERATOR);
}


static void set_defaults(flatpak_t *f, char **argv)
{
    f->argv0      = argv[0];
    f->gpg_verify = 1;

    if (is_systemd_generator(argv[0]))
        f->command = COMMAND_GENERATE;
    else {
        f->command        = COMMAND_START;
        f->restart_status = 69;
    }
}


static void parse_interval(flatpak_t *f, const char *str)
{
#   define SUFFIX(_e, _s, _l, _p)                                       \
       (!strcmp(_e, _s) || (_l && !strcmp(_e, _l)) || (_p && !strcmp(_e, _p)))
    char   *end;
    double  d;


    d = strtod(str, &end);

    if (end != NULL && *end != '\0') {
        if (SUFFIX(end, "s", "sec", "secs"))
            f->poll_interval = d < 30 ? 30 : (int)d;
        else if (SUFFIX(end, "m", "min", "mins"))
            f->poll_interval = (int)(d * 60);
        else if (SUFFIX(end, "h", "hour", "hours"))
            f->poll_interval = (int)(d * 60 * 60);
        else if (SUFFIX(end, "d", "day", "days"))
            f->poll_interval = (int)(d * 24 * 60 * 60);
        else
            print_usage(f->argv0, EINVAL, "invalid poll interval '%s'", str);
    }
    else
        f->poll_interval = (int)d;

    if (f->poll_interval < FLATPAK_POLL_MIN_INTERVAL)
        f->poll_interval = FLATPAK_POLL_MIN_INTERVAL;

#   undef SUFFIX
}


static void parse_common_options(flatpak_t *f, int argc, char **argv)
{
#   define OPTIONS "-uvndh"
    static struct option options[] = {
        { "allow-unsigned", no_argument, NULL, 'u' },
        { "verbose"       , no_argument, NULL, 'v' },
        { "dry-run"       , no_argument, NULL, 'n' },
        { "debug"         , no_argument, NULL, 'd' },
        { "help"          , no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    const char *command = NULL;
    int         opt;

    while (command == NULL &&
           (opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 'u':
            f->gpg_verify = 0;
            break;

        case 'n':
            f->dry_run = 1;
            break;

        case 'v':
            log_mask <<= 1;
            log_mask  |= 1;
            break;

        case 'h':
            print_usage(argv[0], 0, "");

        case 1:
            optind--;
            command = optarg;
            break;

        case '?':
            print_usage(argv[0], EINVAL, "invalid option");
            break;
        }
    }
#undef OPTIONS
}


static void parse_command(flatpak_t *f, int argc, char **argv)
{
    const char *command;

    if (optind >= argc)
        return;

    if (*argv[optind] == '-' || *argv[optind] == '/')
        return;

    command = argv[optind];

    if (!strcmp(command, "list"))
        f->command = COMMAND_LIST;
    else if (!strcmp(command, "enable") || !strcmp(command, "generate"))
        f->command = COMMAND_GENERATE;
    else if (!strcmp(command, "start"))
        f->command = COMMAND_START;
    else if (!strcmp(optarg, "stop"))
        f->command = COMMAND_STOP;
    else if (!strcmp(optarg, "signal"))
        f->command = COMMAND_SIGNAL;
    else if (!strcmp(optarg, "fetch"))
        f->command = COMMAND_FETCH;
    else if (!strcmp(optarg, "update"))
        f->command = COMMAND_UPDATE;
    else
        print_usage(argv[0], EINVAL, "invalid command '%s'", optarg);

    optind++;
}


static void parse_enable_options(flatpak_t *f, int argc, char **argv)
{
    if (optind + 2 > argc - 1)
        print_usage(argv[0], EINVAL,
                    "missing systemd generator directory arguments");

    if (argv[optind  ][0] == '-' ||
        argv[optind+1][0] == '-' ||
        argv[optind+2][0] == '-') {
        print_usage(argv[0], EINVAL,
                    "can't mix options with systemd generator directories");
    }

    f->dir_service = argv[optind];
    optind += 3;

    if (optind <= argc - 1) {
        f->chosen  = argv + optind;
        f->nchosen = argc - optind;
    }
}


static void parse_start_options(flatpak_t *f, int argc, char **argv)
{
#   define OPTIONS "r:"
    static struct option options[] = {
        { "restart-status", required_argument, NULL, 'r' },
        { NULL, 0, NULL, 0 },
    };

    int   opt;
    char *e;

    if (optind >= argc)
        return;

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            f->restart_status = strtol(optarg, &e, 10);

            if (e && *e) {
                print_usage(argv[0], EINVAL, "invalid restart status '%s'",
                            optarg);
            }
            break;

        case '?':
            print_usage(argv[0], EINVAL, "invalid start option");
            break;
        }
    }
#   undef OPTIONS
}


static void parse_stop_options(flatpak_t *f, int argc, char **argv)
{
#   define OPTIONS "r:s:"
    static struct option options[] = {
        { "remote", required_argument, NULL, 'r' },
        { NULL, 0, NULL, 0 },
    };

    int opt;

    f->user = geteuid();

    if (optind >= argc)
        return;

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            f->user = remote_resolve_user(optarg, NULL, 0);

            if (f->user == (uid_t)-1)
                print_usage(argv[0], EINVAL, "no user for remote '%s'", optarg);
            break;

        case '?':
            print_usage(argv[0], EINVAL, "invalid stop option '%c'", opt);
            break;
        }
    }
#   undef OPTIONS
}


static void parse_signal_name(flatpak_t *f, const char *signame)
{
    const char *p = signame;
    char       *e;

    if (!strncmp(p, "SIG", 3))
        p += 3;

    if (!strcmp(p, "HUP"))
        f->sig = SIGHUP;
    else if (!strcmp(p, "TERM"))
        f->sig = SIGTERM;
    else if (!strcmp(p, "KILL"))
        f->sig = SIGKILL;
    else {
        f->sig = strtol(signame, &e, 10);

        if (e && *e)
            print_usage(f->argv0, EINVAL,
                        "invalid/unsupported signal name/number '%s'", signame);

        if (f->sig < 0)
            f->sig = -f->sig;
    }
}


static void parse_signal_options(flatpak_t *f, int argc, char **argv)
{
#   define OPTIONS "r:s:"
    static struct option options[] = {
        { "remote", required_argument, NULL, 'r' },
        { "signal", required_argument, NULL, 's' },
        { NULL, 0, NULL, 0 },
    };

    int opt;

    f->user = geteuid();
    f->sig  = SIGTERM;

    if (optind >= argc)
        return;

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            f->user = remote_resolve_user(optarg, NULL, 0);

            if (f->user == (uid_t)-1)
                print_usage(argv[0], EINVAL, "no user for remote '%s'", optarg);
            break;

        case 's':
            parse_signal_name(f, optarg);
            break;

        case '?':
            print_usage(argv[0], EINVAL, "invalid signal option '%c'", opt);
            break;
        }
    }
#   undef OPTIONS
}


static void parse_update_options(flatpak_t *f, int argc, char **argv)
{
#   define OPTIONS "-flmi:"
    static struct option options[] = {
        { "fetch"        , no_argument      , NULL, 'f' },
        { "local"        , no_argument      , NULL, 'l' },
        { "monitor"      , no_argument      , NULL, 'm' },
        { "poll-interval", required_argument, NULL, 'i' },
        { NULL, 0, NULL, 0 },
    };

    int opt;

    if (optind >= argc)
        return;

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        if (f->chosen != NULL && opt != 1) {
            print_usage(argv[0], EINVAL,
                        "can't mix options with remote selectors");
        }

        switch (opt) {
        case 'f':
            if (f->command == COMMAND_UPDATE)
                f->command = COMMAND_FETCH;
            else
                print_usage(argv[0], EINVAL, "conflicting 'fetch' option");
            break;

        case 'l':
            if (f->command == COMMAND_UPDATE)
                f->command = COMMAND_APPLY;
            else
                print_usage(argv[0], EINVAL, "conflicting 'local' option");
            break;

        case 'm':
            if (f->poll_interval <= 0)
                f->poll_interval = FLATPAK_POLL_MIN_INTERVAL;
            break;

        case 'i':
            parse_interval(f, optarg);
            break;

        case 1:
            if (f->chosen == NULL) {
                f->chosen  = argv + optind - 1;
                f->nchosen = argc - optind + 1;
            }
            break;

        case '?':
            print_usage(argv[0], EINVAL, "invalid update option");
            break;
        }
    }
#   undef OPTIONS
}


void config_parse_cmdline(flatpak_t *f, int argc, char **argv)
{
    memset(f, 0, sizeof(*f));
    f->sfd = -1;

    set_defaults(f, argv);

    parse_common_options(f, argc, argv);
    parse_command(f, argc, argv);

    switch (f->command) {
    case COMMAND_GENERATE:
        parse_enable_options(f, argc, argv);
        break;
    case COMMAND_START:
        parse_start_options(f, argc, argv);
        break;
    case COMMAND_STOP:
        parse_stop_options(f, argc, argv);
        break;
    case COMMAND_SIGNAL:
        parse_signal_options(f, argc, argv);
        break;
    case COMMAND_UPDATE:
        parse_update_options(f, argc, argv);
        break;
    default:
        break;
    }

    if (f->chosen != NULL) {
        int i;

        for (i = 0; i < f->nchosen; i++) {
            if (f->chosen[i][0] == '-')
                print_usage(argv[0], EINVAL,
                            "can't mix options with remote selectors");
        }
    }

    log_open(f);
}

