#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/libauth.h"

/*
 * chsh — change a user's login shell
 *
 * Usage:
 *   chsh [-s shell] [username]
 *
 * Non-root users may only change their own shell and must authenticate.
 * The new shell must appear in /etc/shells.
 */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-s shell] [username]\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    uid_t real_uid = getuid();
    int is_root = (real_uid == 0);

    char shell[MAX_SHELL] = {0};
    int  has_shell = 0;

    int opt;
    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
        case 's': strncpy(shell, optarg, MAX_SHELL-1); has_shell=1; break;
        default:  usage(argv[0]);
        }
    }

    /* Determine target user */
    const char *target = NULL;
    char self[MAX_USERNAME] = {0};

    passwd_entry *plist = passwd_read_all();

    if (optind < argc) {
        target = argv[optind];
        if (!is_root && strcmp(target, "") != 0) {
            /* Check if it's the same as self */
            passwd_entry *me = passwd_find_uid(plist, real_uid);
            if (!me || strcmp(me->pw_name, target) != 0) {
                fprintf(stderr, "chsh: only root may change another user's shell.\n");
                passwd_free(plist);
                exit(1);
            }
        }
    } else {
        passwd_entry *me = passwd_find_uid(plist, real_uid);
        if (!me) {
            fprintf(stderr, "chsh: cannot determine current user.\n");
            passwd_free(plist);
            exit(1);
        }
        strncpy(self, me->pw_name, MAX_USERNAME-1);
        target = self;
    }

    passwd_entry *pe = passwd_find(plist, target);
    if (!pe) {
        fprintf(stderr, "chsh: user '%s' does not exist.\n", target);
        passwd_free(plist);
        exit(1);
    }

    /* Prompt for shell if not given on command-line */
    if (!has_shell) {
        printf("Current shell: %s\n", pe->pw_shell);
        printf("New shell: ");
        fflush(stdout);
        if (!fgets(shell, sizeof(shell), stdin)) {
            fprintf(stderr, "chsh: error reading shell.\n");
            passwd_free(plist);
            exit(1);
        }
        size_t l = strlen(shell);
        if (l > 0 && shell[l-1] == '\n') shell[l-1] = '\0';
    }

    /* Validate shell */
    if (!shell_is_valid(shell)) {
        fprintf(stderr, "chsh: '%s' is not listed in %s.\n", shell, SHELLS_FILE);
        passwd_free(plist);
        exit(1);
    }

    /* Non-root must authenticate */
    if (!is_root) {
        shadow_entry *slist = shadow_read_all();
        shadow_entry *se    = shadow_find(slist, target);
        char pw[MAX_PASSWORD];
        if (read_password("Password: ", pw, sizeof(pw)) < 0 ||
            !se || !verify_password(pw, se->sp_pwdp)) {
            fprintf(stderr, "chsh: authentication failure.\n");
            secure_zero(pw, sizeof(pw));
            shadow_free(slist);
            passwd_free(plist);
            exit(1);
        }
        secure_zero(pw, sizeof(pw));
        shadow_free(slist);
    }

    strncpy(pe->pw_shell, shell, MAX_SHELL-1);

    if (passwd_write_all(plist) != 0) {
        fprintf(stderr, "chsh: error writing passwd database.\n");
        passwd_free(plist);
        exit(1);
    }

    printf("Shell changed.\n");
    passwd_free(plist);
    return 0;
}
