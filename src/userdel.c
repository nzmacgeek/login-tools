#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * userdel — delete a user
 *
 * Usage: userdel [-r] username
 *   -r   remove home directory and mail spool
 */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-r] username\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "userdel: must be run as root.\n");
        exit(1);
    }

    int remove_home = 0;
    int opt;
    while ((opt = getopt(argc, argv, "r")) != -1) {
        switch (opt) {
        case 'r': remove_home = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (optind >= argc) usage(argv[0]);
    const char *username = argv[optind];

    passwd_entry *plist = passwd_read_all();
    passwd_entry *pe    = passwd_find(plist, username);
    if (!pe) {
        fprintf(stderr, "userdel: user '%s' does not exist.\n", username);
        passwd_free(plist);
        exit(1);
    }

    char home[MAX_PATH];
    strncpy(home, pe->pw_dir, MAX_PATH - 1);
    uid_t uid = pe->pw_uid;

    /* Refuse to delete root */
    if (uid == 0) {
        fprintf(stderr, "userdel: refusing to delete root account.\n");
        passwd_free(plist);
        exit(1);
    }

    /* Remove from passwd */
    passwd_entry *prev = NULL, *cur = plist;
    while (cur) {
        if (strcmp(cur->pw_name, username) == 0) {
            if (prev) prev->next = cur->next;
            else      plist      = cur->next;
            free(cur);
            break;
        }
        prev = cur;
        cur  = cur->next;
    }

    /* Remove from shadow */
    shadow_entry *slist = shadow_read_all();
    shadow_entry *sprev = NULL, *scur = slist;
    while (scur) {
        if (strcmp(scur->sp_namp, username) == 0) {
            if (sprev) sprev->next = scur->next;
            else       slist       = scur->next;
            secure_zero(scur->sp_pwdp, sizeof(scur->sp_pwdp));
            free(scur);
            break;
        }
        sprev = scur;
        scur  = scur->next;
    }

    /* Remove from all groups */
    group_entry *glist = group_read_all();
    for (group_entry *ge = glist; ge; ge = ge->next)
        group_remove_member(ge, username);

    /* Remove private group with same name if it exists */
    group_entry *gprev = NULL, *gcur = glist;
    while (gcur) {
        if (strcmp(gcur->gr_name, username) == 0 && gcur->gr_nmem == 0) {
            if (gprev) gprev->next = gcur->next;
            else       glist       = gcur->next;
            free(gcur);
            break;
        }
        gprev = gcur;
        gcur  = gcur->next;
    }

    int rc = 0;
    rc |= passwd_write_all(plist);
    rc |= shadow_write_all(slist);
    rc |= group_write_all(glist);

    if (rc != 0) {
        fprintf(stderr, "userdel: error writing database files.\n");
        passwd_free(plist); shadow_free(slist); group_free(glist);
        exit(1);
    }

    /* Optionally remove home directory */
    if (remove_home && home[0]) {
        char cmd[MAX_PATH + 16];
        snprintf(cmd, sizeof(cmd), "rm -rf -- %s", home);
        if (system(cmd) != 0)
            fprintf(stderr, "userdel: warning: could not remove '%s'.\n", home);
    }

    passwd_free(plist); shadow_free(slist); group_free(glist);
    return 0;
}
