#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/libauth.h"

/*
 * groupdel — delete a group
 *
 * Usage: groupdel groupname
 *
 * Refuses to delete a group that is the primary group of any user.
 */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s groupname\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "groupdel: must be run as root.\n");
        exit(1);
    }
    if (argc != 2) usage(argv[0]);
    const char *groupname = argv[1];

    group_entry *glist = group_read_all();
    group_entry *ge    = group_find(glist, groupname);
    if (!ge) {
        fprintf(stderr, "groupdel: group '%s' does not exist.\n", groupname);
        group_free(glist);
        exit(1);
    }

    gid_t gid = ge->gr_gid;

    /* Check no user has this as their primary group */
    passwd_entry *plist = passwd_read_all();
    for (passwd_entry *pe = plist; pe; pe = pe->next) {
        if (pe->pw_gid == gid) {
            fprintf(stderr,
                    "groupdel: cannot remove group '%s': it is the primary group "
                    "of user '%s'.\n", groupname, pe->pw_name);
            passwd_free(plist);
            group_free(glist);
            exit(1);
        }
    }
    passwd_free(plist);

    /* Remove the entry */
    group_entry *prev = NULL, *cur = glist;
    while (cur) {
        if (strcmp(cur->gr_name, groupname) == 0) {
            if (prev) prev->next = cur->next;
            else      glist      = cur->next;
            free(cur);
            break;
        }
        prev = cur;
        cur  = cur->next;
    }

    if (group_write_all(glist) != 0) {
        fprintf(stderr, "groupdel: error writing group database.\n");
        group_free(glist);
        exit(1);
    }

    group_free(glist);
    return 0;
}
