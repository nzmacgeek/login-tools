#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/libauth.h"

/*
 * userlock — lock or unlock a user account
 *
 * Usage:
 *   userlock -l username    lock account
 *   userlock -u username    unlock account
 *   userlock -s username    show lock status
 *
 * Locking prepends '!' to the password hash in /etc/shadow.
 * Unlocking removes a leading '!'.
 */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -l|-u|-s username\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "userlock: must be run as root.\n");
        exit(1);
    }

    int lock = 0, unlock = 0, status = 0;
    int opt;
    while ((opt = getopt(argc, argv, "lus")) != -1) {
        switch (opt) {
        case 'l': lock   = 1; break;
        case 'u': unlock = 1; break;
        case 's': status = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (optind >= argc) usage(argv[0]);
    if (lock + unlock + status != 1) {
        fprintf(stderr, "userlock: specify exactly one of -l, -u, or -s.\n");
        exit(1);
    }
    const char *username = argv[optind];

    shadow_entry *slist = shadow_read_all();
    shadow_entry *se    = shadow_find(slist, username);
    if (!se) {
        fprintf(stderr, "userlock: user '%s' not found in shadow database.\n", username);
        shadow_free(slist);
        exit(1);
    }

    if (status) {
        int is_locked = (se->sp_pwdp[0] == '!' || se->sp_pwdp[0] == '*');
        printf("%s: %s\n", username, is_locked ? "locked" : "unlocked");
        shadow_free(slist);
        return 0;
    }

    if (lock) {
        if (se->sp_pwdp[0] == '!') {
            fprintf(stderr, "userlock: account '%s' is already locked.\n", username);
            shadow_free(slist);
            exit(0);
        }
        /* Prepend '!' to lock — shift content right by one byte */
        size_t pwlen = strlen(se->sp_pwdp);
        memmove(se->sp_pwdp + 1, se->sp_pwdp,
                pwlen < (size_t)(MAX_HASH - 2) ? pwlen + 1 : MAX_HASH - 2);
        se->sp_pwdp[0] = '!';
        se->sp_pwdp[MAX_HASH - 1] = '\0';
        printf("userlock: account '%s' locked.\n", username);
    }

    if (unlock) {
        if (se->sp_pwdp[0] != '!') {
            fprintf(stderr, "userlock: account '%s' is not locked.\n", username);
            shadow_free(slist);
            exit(0);
        }
        memmove(se->sp_pwdp, se->sp_pwdp + 1, strlen(se->sp_pwdp));
        printf("userlock: account '%s' unlocked.\n", username);
    }

    if (shadow_write_all(slist) != 0) {
        fprintf(stderr, "userlock: error writing shadow database.\n");
        shadow_free(slist);
        exit(1);
    }

    shadow_free(slist);
    return 0;
}
