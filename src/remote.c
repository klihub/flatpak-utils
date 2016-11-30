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


static void r_free(gpointer data)
{
    remote_t *r = data;

    if (r == NULL)
        return;

    g_object_unref(r->r);
    free(r);
}


static int remote_cb(flatpak_t *f, FlatpakRemote *r, const char *name)
{
    remote_t *remote;
    uid_t     uid;

    if ((uid = remote_resolve_user(name, NULL, 0)) == (uid_t)-1) {
        log_warning("remote %s: no associated user, ignoring...", name);
        return 0;
    }

    if (uid != f->session_uid && f->session_uid != 0) {
        log_warning("remote %s: for other user %d (!= %d), ignoring...", name,
                    f->session_uid, uid);
        return 0;
    }

    if ((remote = calloc(1, sizeof(*r))) == NULL)
        return -1;

    remote->r    = g_object_ref(r);
    remote->name = name;
    remote->uid  = uid;

    if (!g_hash_table_insert(f->remotes, (void *)name, remote)) {
        r_free(remote);
        return -1;
    }

    log_info("discovered remote %s", remote->name);

    return 0;
}


int remote_discover(flatpak_t *f)
{
    if (f->remotes != NULL)
        return 0;

    f->remotes = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_free);

    if (f->remotes == NULL)
        return -1;

    if (ftpk_discover_remotes(f, remote_cb) < 0)
        return -1;

    return 0;
}


void remote_forget(flatpak_t *f)
{
    g_hash_table_destroy(f->remotes);
    f->remotes = NULL;
}


remote_t *remote_lookup(flatpak_t *f, const char *name)
{
    return f && f->remotes ? g_hash_table_lookup(f->remotes, name) : NULL;
}


remote_t *remote_for_user(flatpak_t *f, uid_t uid)
{
    remote_t *r;

    foreach_remote(f, r) {
        if (r->uid == uid)
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

    pw = getpwuid(r->uid);

    if (pw == NULL)
        return NULL;

    strncpy(buf, pw->pw_name, size - 1);
    buf[size - 1] = '\0';

    return buf;
}


const char *remote_url(remote_t *r, char *buf, size_t size)
{
    static char  url[1024];
    char        *p;

    p = flatpak_remote_get_url(r->r);

    if (buf == NULL) {
        buf  = url;
        size = sizeof(url);
    }

    strncpy(buf, p, size - 1);
    buf[size - 1] = '\0';

    return buf;
}
