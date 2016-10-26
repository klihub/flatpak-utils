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
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "generator.h"


char *fs_mkpath(char *path, size_t size, const char *fmt, ...)
{
    static char buf[PATH_MAX];
    va_list ap;
    int n;

    if (path == NULL) {
        path = buf;
        size = sizeof(buf);
    }
    else if (size > PATH_MAX)
        size = PATH_MAX;

    va_start(ap, fmt);
    n = vsnprintf(path, size, fmt, ap);
    va_end(ap);

    if (n < 0 || n >= (int)size)
        goto nametoolong;

    return path;

 nametoolong:
    errno = ENAMETOOLONG;
    return NULL;
}


int fs_mkdir(const char *path, mode_t mode)
{
    const char *p;
    char       *q, buf[PATH_MAX];
    int         n, undo[PATH_MAX / 2];
    struct stat st;

    if (path == NULL || path[0] == '\0') {
        errno = path ? EINVAL : EFAULT;
        return -1;
    }

    log_debug("checking/creating '%s'...", path);

    /*
     * Notes:
     *     Our directory creation algorithm logic closely resembles what
     *     'mkdir -p' does. We simply walk the given path component by
     *     component, testing if each one exist. If an existing one is
     *     not a directory we bail out. Missing ones we try to create with
     *     the given mode, bailing out if we fail.
     *
     *     Unlike 'mkdir -p' whenever we fail we clean up by removing
     *     all directories we have created (or at least we try).
     *
     *     Similarly to 'mkdir -p' we don't try to be overly 'smart' about
     *     the path we're handling. Especially we never try to treat '..'
     *     in any special way. This is very much intentional and the idea
     *     is to let the caller try to create a full directory hierarchy
     *     atomically, either succeeeding creating the full hierarchy, or
     *     none of it. To see the consequences of these design choices,
     *     consider what are the possible outcomes of a call like
     *
     *       fs_mkdir("/home/kli/bin/../sbin/../scripts/../etc/../doc", 0755);
     */

    p = path;
    q = buf;
    n = 0;
    while (1) {
        if (q - buf >= (ptrdiff_t)sizeof(buf) - 1) {
            errno = ENAMETOOLONG;
            goto cleanup;
        }

        if (*p && *p != '/') {
            *q++ = *p++;
            continue;
        }

        *q = '\0';

        if (q != buf) {
            log_debug("checking/creating '%s'...", buf);

            if (stat(buf, &st) < 0) {
                if (errno != ENOENT)
                    goto cleanup;

                if (mkdir(buf, mode) < 0)
                    goto cleanup;

                undo[n++] = q - buf;
            }
            else {
                if (!S_ISDIR(st.st_mode)) {
                    errno = ENOTDIR;
                    goto cleanup;
                }
            }
        }

        while (*p == '/')
            p++;

        if (!*p)
            break;

        *q++ = '/';
    }

    return 0;

 cleanup:
    while (--n >= 0) {
        buf[undo[n]] = '\0';
        log_debug("cleaning up '%s'...", buf);
        rmdir(buf);
    }

    return -1;
}


int fs_mkdirp(mode_t mode, const char *fmt, ...)
{
    va_list ap;
    char path[PATH_MAX];
    int n;

    va_start(ap, fmt);
    n = vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);

    if (n < 0 || n >= (int)sizeof(path))
        goto nametoolong;

    return fs_mkdir(path, mode);

 nametoolong:
    errno = ENAMETOOLONG;
    return -1;
}


int fs_symlink(const char *path, const char *dst)
{
    struct stat stp, std;

    if (lstat(path, &stp) < 0)
        return -1;

    if (!S_ISLNK(stp.st_mode))
        return 0;

    if (dst == NULL)
        return 1;

    if (stat(path, &std) < 0)
        return 0;

    if (stat(path, &stp) < 0)
        return -1;

    if (stp.st_dev == std.st_dev && stp.st_ino == std.st_ino)
        return 1;
    else
        return 0;
}


char *fs_service_path(generator_t *g, const char *usr, char *path, size_t size)
{
    return fs_mkpath(path, size, "%s/flatpak-%s-session.service",
                     g->dir_service, usr);
}


char *fs_service_link(generator_t *g, const char *usr, char *path, size_t size)
{
    return fs_mkpath(path, size, "%s/flatpak.target.wants/%s-session.service",
                     g->dir_service, usr);
}


int fs_prepare_directories(generator_t *g)
{
    return fs_mkdirp(0755, fs_mkpath(NULL, 0, "%s/flatpak.target.wants",
                                     g->dir_service));
}
