#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * groupadd — create a new group
 *
 * Usage: groupadd [-g gid] [-r] groupname
 *   -g gid   specify GID
 *   -r       create system group (GID < 1000)
 */

#define MIN_GID     1000
#define MIN_SYS_GID 100

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-g gid] [-r] groupname\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "groupadd: must be run as root.\n");
        exit(1);
    }

    gid_t gid_opt = (gid_t)-1;
    int   system_grp = 0;
    int   opt;
    while ((opt = getopt(argc, argv, "g:r")) != -1) {
        switch (opt) {
        case 'g': gid_opt    = (gid_t)atoi(optarg); break;
        case 'r': system_grp = 1;                    break;
        default:  usage(argv[0]);
        }
    }
    if (optind >= argc) usage(argv[0]);
    const char *groupname = argv[optind];

    if (!is_valid_username(groupname)) {
        fprintf(stderr, "groupadd: invalid group name '%s'.\n", groupname);
        exit(1);
    }

    group_entry *glist = group_read_all();
    if (group_find(glist, groupname)) {
        fprintf(stderr, "groupadd: group '%s' already exists.\n", groupname);
        group_free(glist);
        exit(1);
    }

    gid_t gid = (gid_opt != (gid_t)-1)
              ? gid_opt
              : group_next_gid(glist, system_grp ? MIN_SYS_GID : MIN_GID);

    group_entry *ng = calloc(1, sizeof(*ng));
    strncpy(ng->gr_name,   groupname, MAX_USERNAME - 1);
    strncpy(ng->gr_passwd, "x",       sizeof(ng->gr_passwd) - 1);
    ng->gr_gid  = gid;
    ng->gr_nmem = 0;

    /* Append to list */
    if (!glist) {
        glist = ng;
    } else {
        group_entry *tail = glist;
        while (tail->next) tail = tail->next;
        tail->next = ng;
    }

    if (group_write_all(glist) != 0) {
        fprintf(stderr, "groupadd: error writing group database.\n");
        group_free(glist);
        exit(1);
    }

    group_free(glist);
    return 0;
}
