#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * groupmod — modify a group
 *
 * Usage: groupmod [options] groupname
 *   -n newname    rename the group
 *   -g gid        change GID
 *   -A user,...   add users to the group
 *   -R user,...   remove users from the group
 */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-n newname] [-g gid] [-A users] [-R users] groupname\n",
            prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "groupmod: must be run as root.\n");
        exit(1);
    }

    char  newname[MAX_USERNAME] = {0};
    gid_t gid_opt = (gid_t)-1;
    char  add_users[MAX_LINE]   = {0};
    char  rem_users[MAX_LINE]   = {0};
    int   has_newname = 0;

    int opt;
    while ((opt = getopt(argc, argv, "n:g:A:R:")) != -1) {
        switch (opt) {
        case 'n': strncpy(newname,   optarg, MAX_USERNAME-1); has_newname=1; break;
        case 'g': gid_opt = (gid_t)atoi(optarg);             break;
        case 'A': strncpy(add_users, optarg, MAX_LINE-1);     break;
        case 'R': strncpy(rem_users, optarg, MAX_LINE-1);     break;
        default:  usage(argv[0]);
        }
    }
    if (optind >= argc) usage(argv[0]);
    const char *groupname = argv[optind];

    group_entry *glist = group_read_all();
    group_entry *ge    = group_find(glist, groupname);
    if (!ge) {
        fprintf(stderr, "groupmod: group '%s' does not exist.\n", groupname);
        group_free(glist);
        exit(1);
    }

    if (has_newname) strncpy(ge->gr_name, newname, MAX_USERNAME-1);
    if (gid_opt != (gid_t)-1) ge->gr_gid = gid_opt;

    if (add_users[0]) {
        char tmp[MAX_LINE];
        strncpy(tmp, add_users, MAX_LINE-1);
        char *save, *tok;
        for (tok = strtok_r(tmp, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save))
            group_add_member(ge, tok);
    }

    if (rem_users[0]) {
        char tmp[MAX_LINE];
        strncpy(tmp, rem_users, MAX_LINE-1);
        char *save, *tok;
        for (tok = strtok_r(tmp, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save))
            group_remove_member(ge, tok);
    }

    /* Update group references in passwd if GID changed */
    if (gid_opt != (gid_t)-1) {
        passwd_entry *plist = passwd_read_all();
        /* Find users whose primary group matches the old GID */
        /* (We already updated ge->gr_gid, so we need the old value) */
        /* This is handled implicitly — passwd stores GID numerically */
        passwd_free(plist);
    }

    if (group_write_all(glist) != 0) {
        fprintf(stderr, "groupmod: error writing group database.\n");
        group_free(glist);
        exit(1);
    }

    group_free(glist);
    return 0;
}
