#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * useradd — create a new user
 *
 * Usage: useradd [options] username
 *   -u uid        specify UID
 *   -g gid        primary group GID
 *   -G group,...  supplementary groups
 *   -d dir        home directory (default /home/<username>)
 *   -s shell      login shell (default /bin/sh)
 *   -c comment    GECOS comment
 *   -m            create home directory
 *   -r            create system account (UID < 1000)
 */

#define MIN_UID      1000
#define MIN_SYS_UID  100
#define MIN_GID      1000
#define MIN_SYS_GID  100

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-u uid] [-g gid] [-G groups] [-d home] [-s shell]\n"
            "       %*s [-c comment] [-m] [-r] username\n",
            prog, (int)strlen(prog), "");
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "useradd: must be run as root.\n");
        exit(1);
    }

    uid_t  uid_opt = (uid_t)-1;
    gid_t  gid_opt = (gid_t)-1;
    char   home_opt[MAX_PATH]  = {0};
    char   shell_opt[MAX_SHELL] = "/bin/sh";
    char   gecos_opt[MAX_GECOS] = {0};
    char   groups_opt[MAX_LINE] = {0};
    int    create_home = 0;
    int    system_acct = 0;

    int opt;
    while ((opt = getopt(argc, argv, "u:g:G:d:s:c:mr")) != -1) {
        switch (opt) {
        case 'u': uid_opt  = (uid_t)atoi(optarg); break;
        case 'g': gid_opt  = (gid_t)atoi(optarg); break;
        case 'G': strncpy(groups_opt, optarg, MAX_LINE - 1); break;
        case 'd': strncpy(home_opt, optarg, MAX_PATH - 1); break;
        case 's': strncpy(shell_opt, optarg, MAX_SHELL - 1); break;
        case 'c': strncpy(gecos_opt, optarg, MAX_GECOS - 1); break;
        case 'm': create_home = 1; break;
        case 'r': system_acct = 1; break;
        default:  usage(argv[0]);
        }
    }

    if (optind >= argc) usage(argv[0]);
    const char *username = argv[optind];

    if (!is_valid_username(username)) {
        fprintf(stderr, "useradd: invalid username '%s'.\n", username);
        exit(1);
    }

    passwd_entry *plist = passwd_read_all();
    shadow_entry *slist = shadow_read_all();
    group_entry  *glist = group_read_all();

    /* Check user does not already exist */
    if (passwd_find(plist, username)) {
        fprintf(stderr, "useradd: user '%s' already exists.\n", username);
        passwd_free(plist); shadow_free(slist); group_free(glist);
        exit(1);
    }

    /* Assign UID */
    uid_t uid = (uid_opt != (uid_t)-1) ? uid_opt
              : passwd_next_uid(plist, system_acct ? MIN_SYS_UID : MIN_UID);

    /* Assign primary GID */
    gid_t gid;
    if (gid_opt != (gid_t)-1) {
        gid = gid_opt;
    } else {
        /* Create a group with the same name */
        gid = group_next_gid(glist, system_acct ? MIN_SYS_GID : MIN_GID);
        group_entry *ng = calloc(1, sizeof(*ng));
        strncpy(ng->gr_name, username, MAX_USERNAME - 1);
        strncpy(ng->gr_passwd, "x", sizeof(ng->gr_passwd) - 1);
        ng->gr_gid  = gid;
        ng->gr_nmem = 0;
        ng->next    = glist;
        glist       = ng;
    }

    /* Home directory */
    if (!home_opt[0])
        snprintf(home_opt, MAX_PATH, "/home/%s", username);

    /* Build passwd entry */
    passwd_entry *ne = calloc(1, sizeof(*ne));
    strncpy(ne->pw_name,   username,   MAX_USERNAME - 1);
    strncpy(ne->pw_passwd, "x",        sizeof(ne->pw_passwd) - 1);
    ne->pw_uid = uid;
    ne->pw_gid = gid;
    strncpy(ne->pw_gecos, gecos_opt,  MAX_GECOS - 1);
    strncpy(ne->pw_dir,   home_opt,   MAX_PATH  - 1);
    strncpy(ne->pw_shell, shell_opt,  MAX_SHELL - 1);
    /* Append to end of list */
    if (!plist) {
        plist = ne;
    } else {
        passwd_entry *tail = plist;
        while (tail->next) tail = tail->next;
        tail->next = ne;
    }

    /* Build shadow entry (locked until password is set) */
    shadow_entry *nse = calloc(1, sizeof(*nse));
    strncpy(nse->sp_namp, username, MAX_USERNAME - 1);
    strncpy(nse->sp_pwdp, "!",     MAX_HASH - 1);
    nse->sp_lstchg = days_since_epoch();
    nse->sp_min    = -1;
    nse->sp_max    = -1;
    nse->sp_warn   = -1;
    nse->sp_inact  = -1;
    nse->sp_expire = -1;
    if (!slist) {
        slist = nse;
    } else {
        shadow_entry *tail = slist;
        while (tail->next) tail = tail->next;
        tail->next = nse;
    }

    /* Add to supplementary groups */
    if (groups_opt[0]) {
        char tmp[MAX_LINE];
        strncpy(tmp, groups_opt, MAX_LINE - 1);
        char *save, *tok;
        for (tok = strtok_r(tmp, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save)) {
            group_entry *ge = group_find(glist, tok);
            if (!ge) {
                fprintf(stderr, "useradd: warning: group '%s' does not exist.\n", tok);
                continue;
            }
            group_add_member(ge, username);
        }
    }

    /* Write files */
    int rc = 0;
    rc |= passwd_write_all(plist);
    rc |= shadow_write_all(slist);
    rc |= group_write_all(glist);

    if (rc != 0) {
        fprintf(stderr, "useradd: error writing database files.\n");
        passwd_free(plist); shadow_free(slist); group_free(glist);
        exit(1);
    }

    /* Create home directory */
    if (create_home) {
        if (ensure_dir(home_opt, 0755) == 0) {
            (void)chown(home_opt, uid, gid);
            chmod(home_opt, 0700);
        } else {
            fprintf(stderr, "useradd: warning: could not create home directory '%s'.\n",
                    home_opt);
        }
    }

    passwd_free(plist); shadow_free(slist); group_free(glist);
    return 0;
}
