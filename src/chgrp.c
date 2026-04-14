#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <getopt.h>

/*
 * chgrp — change file group ownership
 *
 * Usage: chgrp [-R] [-v] [-c] GROUP FILE...
 *   -R  apply recursively
 *   -v  verbose
 *   -c  report only when a change is made
 */

static int flag_recursive = 0;
static int flag_verbose   = 0;
static int flag_changes   = 0;

/* ---- group resolution ---------------------------------------------------- */

/* Resolve a group name or numeric string to a gid.
 * Returns 0 on success, 1 on error. */
static int resolve_group(const char *spec, gid_t *gid)
{
    char *end;
    long v = strtol(spec, &end, 10);
    if (*end == '\0') {
        *gid = (gid_t)v;
        return 0;
    }
    struct group *gr = getgrnam(spec);
    if (!gr) {
        fprintf(stderr, "chgrp: invalid group: '%s'\n", spec);
        return 1;
    }
    *gid = gr->gr_gid;
    return 0;
}

/* ---- core operation ------------------------------------------------------ */

static int do_chgrp(const char *path, gid_t gid)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "chgrp: cannot stat '%s': %s\n", path, strerror(errno));
        return 1;
    }

    gid_t old_gid = st.st_gid;

    if (lchown(path, (uid_t)-1, gid) != 0) {
        fprintf(stderr, "chgrp: changing group of '%s': %s\n",
                path, strerror(errno));
        return 1;
    }

    if (flag_verbose || (flag_changes && old_gid != gid)) {
        if (old_gid != gid)
            printf("changed group of '%s' from %u to %u\n", path, old_gid, gid);
        else if (flag_verbose)
            printf("group of '%s' retained as %u\n", path, old_gid);
    }
    return 0;
}

static int chgrp_tree(const char *path, gid_t gid);

static int descend_dir(const char *path, gid_t gid)
{
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "chgrp: cannot open directory '%s': %s\n",
                path, strerror(errno));
        return 1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        rc |= chgrp_tree(child, gid);
    }
    closedir(d);
    return rc;
}

static int chgrp_tree(const char *path, gid_t gid)
{
    int rc = do_chgrp(path, gid);
    struct stat st;
    if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
        rc |= descend_dir(path, gid);
    return rc;
}

/* ---- main ---------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-R] [-v] [-c] GROUP FILE...\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "chgrp: must be run as root.\n");
        exit(1);
    }

    int opt;
    while ((opt = getopt(argc, argv, "Rvc")) != -1) {
        switch (opt) {
        case 'R': flag_recursive = 1; break;
        case 'v': flag_verbose   = 1; break;
        case 'c': flag_changes   = 1; break;
        default:  usage(argv[0]);
        }
    }

    if (optind + 1 >= argc)
        usage(argv[0]);

    gid_t gid;
    if (resolve_group(argv[optind++], &gid) != 0)
        exit(1);

    int rc = 0;
    for (; optind < argc; optind++) {
        if (flag_recursive)
            rc |= chgrp_tree(argv[optind], gid);
        else
            rc |= do_chgrp(argv[optind], gid);
    }
    return rc;
}
