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

#include "generator.h"

static void print_usage(const char *argv0, int exit_code, const char *fmt, ...)
{
    va_list ap;

    if (fmt && *fmt) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }

    fprintf(stderr, "usage: %s [options] normal early late\n"
            "\n"
            "Search for flatpak-providers and generate a systemd service\n"
            "for each provider found. The per-provider systemd session will\n"
            "create sessions for all found providers and start all flatpak\n"
            "applications from that provider within the session.\n"
            "\n"
            "Every provider is expected to have a single flatpak repository\n"
            "registered for it. Every flatpak repository must have a similarly\n"
            "named user associated with it. Every flatpak from a repository\n"
            "will be started within the session for the repository user.\n"
            "\n"
            "The possible opions are:\n"
            "  -t  --template <name>     template to generate services from\n"
            "  -n, --dry-run             just print, don't generate anything\n"
            "  -v, --verbose             increase logging verbosity\n"
            "  -h, --help                print this help message\n", argv0);

    if (exit_code < 0)
        return;
    else
        exit(exit_code);
}


static void set_defaults(generator_t *g, char **argv)
{
    g->argv0         = argv[0];
    g->f             = NULL;
    g->dry_run       = 0;
    g->dir_normal    = NULL;
    g->dir_early     = NULL;
    g->dir_late      = NULL;
    g->path_template = PATH_TEMPLATE;
}


void config_parse_cmdline(generator_t *g, int argc, char **argv)
{
#   define OPTIONS "t:nvh"
    static struct option options[] = {
        { "template"    , required_argument, NULL, 't' },
        { "dry-run"     , no_argument      , NULL, 'n' },
        { "verbose"     , no_argument      , NULL, 'v' },
        { "help"        , no_argument      , NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;

    set_defaults(g, argv);

    while ((opt = getopt_long(argc, argv, OPTIONS, options, NULL)) != -1) {
        switch (opt) {
        case 't':
            g->path_template = optarg;
            break;

        case 'n':
            g->dry_run = 1;
            break;

        case 'v':
            log_mask <<= 1;
            log_mask  |= 1;
            break;

        case 'h':
            print_usage(argv[0], 0, "");
            break;

        case '?':
            print_usage(argv[0], EINVAL, "", opt);
            break;

        default:
            print_usage(argv[0], EINVAL, "invalid argument '%c'", opt);
            break;
        }
    }

    log_open(g);

    if (argc != optind + 3)
        print_usage(argv[0], EINVAL, "Missing directory arguments.");

    g->dir_normal  = argv[optind];
    g->dir_early   = argv[optind + 1];
    g->dir_late    = argv[optind + 2];

    g->dir_service = g->dir_normal;
}

