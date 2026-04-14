#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>

/*
 * chown — change file owner and group
 *
 * Usage: chown [-R] [-v] [-c] OWNER[:GROUP] FILE...
 *        chown [-R] [-v] [-c] :GROUP FILE...
 *   -R  apply recursively
 *   -v  verbose
 *   -c  report only when a change is made
 */

static int flag_recursive = 0;
static int flag_verbose   = 0;
static int flag_changes   = 0;

/* ---- owner/group resolution --------------------------------------------- */

/* Resolve owner[:group] spec into *uid and *gid.
 * -1 means "do not change".  Returns 0 on success, 1 on error. */
static int resolve_spec(const char *spec, uid_t *uid, gid_t *gid)
{
    *uid = (uid_t)-1;
    *gid = (gid_t)-1;

    /* Split on the first ':' */
    char buf[512];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *colon = strchr(buf, ':');
    char *owner_str = buf;
    char *group_str = NULL;

    if (colon) {
        *colon = '\0';
        group_str = colon + 1;
    }

    /* Resolve owner */
    if (*owner_str) {
        char *end;
        long v = strtol(owner_str, &end, 10);
        if (*end == '\0') {
            *uid = (uid_t)v;
        } else {
            struct passwd *pw = getpwnam(owner_str);
            if (!pw) {
                fprintf(stderr, "chown: invalid user: '%s'\n", owner_str);
                return 1;
            }
            *uid = pw->pw_uid;
            /* When no explicit group given, also apply user's primary group */
            if (group_str == NULL || *group_str == '\0')
                *gid = pw->pw_gid;
        }
    }

    /* Resolve group (if provided after ':') */
    if (group_str && *group_str) {
        char *end;
        long v = strtol(group_str, &end, 10);
        if (*end == '\0') {
            *gid = (gid_t)v;
        } else {
            struct group *gr = getgrnam(group_str);
            if (!gr) {
                fprintf(stderr, "chown: invalid group: '%s'\n", group_str);
                return 1;
            }
            *gid = gr->gr_gid;
        }
    }

    return 0;
}

/* ---- core operation ------------------------------------------------------ */

static int do_chown(const char *path, uid_t uid, gid_t gid)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "chown: cannot stat '%s': %s\n", path, strerror(errno));
        return 1;
    }

    uid_t old_uid = st.st_uid;
    gid_t old_gid = st.st_gid;

    if (lchown(path, uid, gid) != 0) {
        fprintf(stderr, "chown: changing ownership of '%s': %s\n",
                path, strerror(errno));
        return 1;
    }

    uid_t new_uid = (uid != (uid_t)-1) ? uid : old_uid;
    gid_t new_gid = (gid != (gid_t)-1) ? gid : old_gid;

    if (flag_verbose || (flag_changes && (old_uid != new_uid || old_gid != new_gid))) {
        if (old_uid != new_uid || old_gid != new_gid)
            printf("changed ownership of '%s' from %u:%u to %u:%u\n",
                   path, old_uid, old_gid, new_uid, new_gid);
        else if (flag_verbose)
            printf("ownership of '%s' retained as %u:%u\n",
                   path, old_uid, old_gid);
    }
    return 0;
}

static int chown_tree(const char *path, uid_t uid, gid_t gid);

static int descend_dir(const char *path, uid_t uid, gid_t gid)
{
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "chown: cannot open directory '%s': %s\n",
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
        rc |= chown_tree(child, uid, gid);
    }
    closedir(d);
    return rc;
}

static int chown_tree(const char *path, uid_t uid, gid_t gid)
{
    int rc = do_chown(path, uid, gid);
    struct stat st;
    if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
        rc |= descend_dir(path, uid, gid);
    return rc;
}

/* ---- main ---------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-R] [-v] [-c] OWNER[:GROUP] FILE...\n"
            "       %*s [-R] [-v] [-c] :GROUP FILE...\n",
            prog, (int)strlen(prog), "");
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "chown: must be run as root.\n");
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

    uid_t uid;
    gid_t gid;
    if (resolve_spec(argv[optind++], &uid, &gid) != 0)
        exit(1);

    int rc = 0;
    for (; optind < argc; optind++) {
        if (flag_recursive)
            rc |= chown_tree(argv[optind], uid, gid);
        else
            rc |= do_chown(argv[optind], uid, gid);
    }
    return rc;
}
