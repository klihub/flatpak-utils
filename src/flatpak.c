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
#include <pwd.h>
#include <sys/types.h>

#include "generator.h"

uid_t fp_resolve_user(FlatpakRemote *r, char *usrbuf, size_t size)
{
    const char    *rname = flatpak_remote_get_name(r);
    char           name[256], buf[1024];
    struct passwd *pwd, ent;

    if (usrbuf != NULL)
        *usrbuf = '\0';

    if (getpwnam_r(rname, &ent, buf, sizeof(buf), &pwd) == 0 && pwd != NULL) {
        snprintf(name, sizeof(name), "flatpak user for %s", rname);

        if (strcmp(pwd->pw_gecos, name) != 0)
            pwd = NULL;
    }

    if (pwd == NULL)
        getpwnam_r(name, &ent, buf, sizeof(buf), &pwd);

    if (pwd == NULL)
        return (uid_t)-1;

    if (usrbuf != NULL)
        snprintf(usrbuf, size, "%.*s", (int)size-1, pwd->pw_name);

    return pwd->pw_uid;
}


int fp_discover_remotes(generator_t *g)
{
    GError        *err = NULL;
    FlatpakRemote *r;
    int            i;

    g->f = flatpak_installation_new_system(NULL, &err);

    if (g->f == NULL) {
        log_error("failed to initialize flatpak library (%s: %d:%s)",
                  g_quark_to_string(err->domain), err->code, err->message);
        goto fail;
    }

    g->remotes = flatpak_installation_list_remotes(g->f, NULL, &err);

    if (g->remotes == NULL) {
        log_error("failed to query flatpak remotes (%s: %d:%s)",
                  g_quark_to_string(err->domain), err->code, err->message);
        goto fail;
    }

    log_info("discovered %d remotes", g->remotes->len);

    for (i = 0; i < (int)g->remotes->len; i++) {
        r = g_ptr_array_index(g->remotes, i);

        log_info("found remote '%s' (%s)", flatpak_remote_get_name(r),
                 flatpak_remote_get_url(r));

        if (flatpak_remote_get_disabled(r)) {
            log_warning("remote %s disabled, skipping...",
                        flatpak_remote_get_name(r));

            g_ptr_array_remove(g->remotes, r);
            i--;

            continue;
        }

#if 0
        if (!flatpak_remote_get_gpg_verify(r)) {
            log_warning("remote %s can't be GPG-verified, ignoring...",
                        flatpak_remote_get_name(r));

            g_ptr_array_remove(g->remotes, r);
            i--;

            continue;
        }
#endif
    }


    return 0;

 fail:
    return -1;
}


