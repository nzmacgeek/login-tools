#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * usermod — modify a user account
 *
 * Usage: usermod [options] username
 *   -u uid        new UID
 *   -g gid        new primary GID
 *   -G group,...  set supplementary groups (replaces existing)
 *   -a            append to supplementary groups (use with -G)
 *   -d dir        new home directory
 *   -s shell      new login shell
 *   -c comment    new GECOS comment
 *   -l newname    new login name
 *   -e date       account expiry date (YYYY-MM-DD, or "" to clear)
 *   -L            lock the account
 *   -U            unlock the account
 */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-u uid] [-g gid] [-G groups [-a]] [-d home] [-s shell]\n"
            "       %*s [-c comment] [-l newname] [-e date] [-L|-U] username\n",
            prog, (int)strlen(prog), "");
    exit(1);
}

/* Parse YYYY-MM-DD to days since epoch (1970-01-01). Returns -1 on error. */
static long parse_date(const char *s)
{
    if (!s || !*s) return -1;
    int y, m, d;
    if (sscanf(s, "%d-%d-%d", &y, &m, &d) != 3) return -1;
    /* Simplified Gregorian day count */
    struct tm t = {0};
    t.tm_year = y - 1900;
    t.tm_mon  = m - 1;
    t.tm_mday = d;
    time_t ts = mktime(&t);
    if (ts == (time_t)-1) return -1;
    return (long)(ts / 86400);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "usermod: must be run as root.\n");
        exit(1);
    }

    uid_t  uid_opt    = (uid_t)-1;
    gid_t  gid_opt    = (gid_t)-1;
    char   home_opt[MAX_PATH]   = {0};
    char   shell_opt[MAX_SHELL] = {0};
    char   gecos_opt[MAX_GECOS] = {0};
    char   newname[MAX_USERNAME]= {0};
    char   groups_opt[MAX_LINE] = {0};
    char   expire_opt[32]       = {0};
    int    append_groups = 0;
    int    lock   = 0;
    int    unlock = 0;
    int    has_uid=0, has_gid=0, has_home=0, has_shell=0,
           has_gecos=0, has_newname=0, has_groups=0, has_expire=0;

    int opt;
    while ((opt = getopt(argc, argv, "u:g:G:ad:s:c:l:e:LU")) != -1) {
        switch (opt) {
        case 'u': uid_opt = (uid_t)atoi(optarg);             has_uid=1;     break;
        case 'g': gid_opt = (gid_t)atoi(optarg);             has_gid=1;     break;
        case 'G': strncpy(groups_opt, optarg, MAX_LINE-1);   has_groups=1;  break;
        case 'a': append_groups = 1;                                         break;
        case 'd': strncpy(home_opt,  optarg, MAX_PATH-1);    has_home=1;    break;
        case 's': strncpy(shell_opt, optarg, MAX_SHELL-1);   has_shell=1;   break;
        case 'c': strncpy(gecos_opt, optarg, MAX_GECOS-1);   has_gecos=1;   break;
        case 'l': strncpy(newname,   optarg, MAX_USERNAME-1);has_newname=1; break;
        case 'e': strncpy(expire_opt,optarg, 31);             has_expire=1;  break;
        case 'L': lock   = 1; break;
        case 'U': unlock = 1; break;
        default:  usage(argv[0]);
        }
    }

    if (optind >= argc) usage(argv[0]);
    const char *username = argv[optind];

    if (lock && unlock) {
        fprintf(stderr, "usermod: -L and -U are mutually exclusive.\n");
        exit(1);
    }

    passwd_entry *plist = passwd_read_all();
    passwd_entry *pe    = passwd_find(plist, username);
    if (!pe) {
        fprintf(stderr, "usermod: user '%s' does not exist.\n", username);
        passwd_free(plist);
        exit(1);
    }

    shadow_entry *slist = shadow_read_all();
    shadow_entry *se    = shadow_find(slist, username);

    /* Apply passwd modifications */
    if (has_uid)     pe->pw_uid = uid_opt;
    if (has_gid)     pe->pw_gid = gid_opt;
    if (has_home)    strncpy(pe->pw_dir,   home_opt,  MAX_PATH-1);
    if (has_shell)   strncpy(pe->pw_shell, shell_opt, MAX_SHELL-1);
    if (has_gecos)   strncpy(pe->pw_gecos, gecos_opt, MAX_GECOS-1);
    if (has_newname) strncpy(pe->pw_name,  newname,   MAX_USERNAME-1);

    /* Apply shadow modifications */
    if (se) {
        if (lock && se->sp_pwdp[0] != '!') {
            /* Prepend '!' to lock — shift content right by one byte */
            size_t pwlen = strlen(se->sp_pwdp);
            memmove(se->sp_pwdp + 1, se->sp_pwdp,
                    pwlen < (size_t)(MAX_HASH - 2) ? pwlen + 1 : MAX_HASH - 2);
            se->sp_pwdp[0] = '!';
            se->sp_pwdp[MAX_HASH - 1] = '\0';
        }
        if (unlock && se->sp_pwdp[0] == '!') {
            memmove(se->sp_pwdp, se->sp_pwdp + 1, strlen(se->sp_pwdp));
        }
        if (has_expire) {
            se->sp_expire = parse_date(expire_opt);
        }
    }

    /* Apply group modifications */
    group_entry *glist = group_read_all();
    if (has_groups) {
        if (!append_groups) {
            /* Remove user from all supplementary groups first */
            for (group_entry *ge = glist; ge; ge = ge->next)
                if (ge->gr_gid != pe->pw_gid)
                    group_remove_member(ge, username);
        }
        char tmp[MAX_LINE];
        strncpy(tmp, groups_opt, MAX_LINE-1);
        char *save, *tok;
        for (tok = strtok_r(tmp, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save)) {
            group_entry *ge = group_find(glist, tok);
            if (!ge) {
                fprintf(stderr, "usermod: warning: group '%s' does not exist.\n", tok);
                continue;
            }
            group_add_member(ge, username);
        }
    }

    /* If username changed, update group membership references */
    if (has_newname) {
        for (group_entry *ge = glist; ge; ge = ge->next) {
            for (int i = 0; i < ge->gr_nmem; i++) {
                if (strcmp(ge->gr_mem[i], username) == 0) {
                    strncpy(ge->gr_mem[i], newname, MAX_USERNAME-1);
                }
            }
        }
        if (se) strncpy(se->sp_namp, newname, MAX_USERNAME-1);
    }

    int rc = 0;
    rc |= passwd_write_all(plist);
    rc |= shadow_write_all(slist);
    rc |= group_write_all(glist);

    if (rc != 0)
        fprintf(stderr, "usermod: error writing database files.\n");

    passwd_free(plist); shadow_free(slist); group_free(glist);
    return rc ? 1 : 0;
}
