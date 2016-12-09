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
#include <pwd.h>
#include <sys/types.h>

#include "flatpak-session.h"


static inline int check_gecos(const char *gecos, const char *usr)
{
    const char *prefix = FLATPAK_GECOS_PREFIX;
    int         size   = sizeof(FLATPAK_GECOS_PREFIX) - 1;

    return !strncmp(gecos, prefix, size) && !strcmp(gecos + size, usr);
}


static uid_t search_user(const char *remote, char *usrbuf, size_t size)
{
    struct passwd *pwd, ent;
    char           buf[1024];

    setpwent();

    while (getpwent_r(&ent, buf, sizeof(buf), &pwd) == 0) {
        if (!check_gecos(pwd->pw_gecos, remote))
            continue;

        if (usrbuf != NULL) {
            strncpy(usrbuf, pwd->pw_name, size - 1);
            usrbuf[size - 1] = '\0';
        }

        return pwd->pw_uid;
    }

    return (uid_t)-1;
}


uid_t remote_resolve_user(const char *remote, char *usrbuf, size_t size)
{
    struct passwd *pwd, ent;
    char           buf[1024];

    if (usrbuf != NULL)
        *usrbuf = '\0';

    if (getpwnam_r(remote, &ent, buf, sizeof(buf), &pwd) == 0 && pwd != NULL) {
        if (check_gecos(pwd->pw_gecos, pwd->pw_name)) {
            if (usrbuf != NULL) {
                strncpy(usrbuf, pwd->pw_name, size - 1);
                usrbuf[size -1] = '\0';
            }

            return pwd->pw_uid;
        }
    }

    return search_user(remote, usrbuf, size);
}


int remote_discover(flatpak_t *f)
{
    return ftpk_discover_remotes(f);
}


remote_t *remote_lookup(flatpak_t *f, const char *name)
{
    return ftpk_lookup_remote(f, name);
}


remote_t *remote_for_user(flatpak_t *f, uid_t uid)
{
    remote_t *r;

    ftpk_foreach_remote(f, r) {
        if (r->session_uid == uid)
            return r;
    }

    return NULL;
}


const char *remote_username(remote_t *r, char *buf, size_t size)
{
    static char    user[256];
    struct passwd *pw;

    if (buf == NULL) {
        buf  = user;
        size = sizeof(user);
    }

    pw = getpwuid(r->session_uid);

    if (pw == NULL)
        return NULL;

    strncpy(buf, pw->pw_name, size - 1);
    buf[size - 1] = '\0';

    return buf;
}


const char *remote_url(remote_t *r, char *buf, size_t size)
{
    static char  url[1024];
    const char  *p;

    p = r->url;

    if (buf == NULL) {
        buf  = url;
        size = sizeof(url);
    }

    strncpy(buf, p, size - 1);
    buf[size - 1] = '\0';

    return buf;
}
