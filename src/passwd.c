#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/libauth.h"

/*
 * passwd — change a user's password
 *
 * Usage:
 *   passwd              change own password
 *   passwd <username>   change another user's password (root only)
 */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [username]\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    uid_t real_uid = getuid();
    int is_root = (real_uid == 0);
    const char *target_user = NULL;

    if (argc > 2) usage(argv[0]);
    if (argc == 2) {
        if (!is_root) {
            fprintf(stderr, "passwd: only root may change another user's password.\n");
            exit(1);
        }
        target_user = argv[1];
    }

    /* Determine target username */
    char self[MAX_USERNAME] = {0};
    if (!target_user) {
        passwd_entry *plist = passwd_read_all();
        passwd_entry *pe = passwd_find_uid(plist, real_uid);
        if (!pe) {
            fprintf(stderr, "passwd: unable to determine your username.\n");
            passwd_free(plist);
            exit(1);
        }
        strncpy(self, pe->pw_name, MAX_USERNAME - 1);
        passwd_free(plist);
        target_user = self;
    }

    /* Load shadow */
    shadow_entry *slist = shadow_read_all();
    shadow_entry *se = shadow_find(slist, target_user);
    if (!se) {
        fprintf(stderr, "passwd: user '%s' does not exist.\n", target_user);
        shadow_free(slist);
        exit(1);
    }

    /* Non-root must verify current password */
    if (!is_root) {
        char current[MAX_PASSWORD];
        if (read_password("Current password: ", current, sizeof(current)) < 0) {
            fprintf(stderr, "passwd: error reading password.\n");
            shadow_free(slist);
            exit(1);
        }
        int ok = verify_password(current, se->sp_pwdp);
        secure_zero(current, sizeof(current));
        if (!ok) {
            fprintf(stderr, "passwd: incorrect current password.\n");
            shadow_free(slist);
            exit(1);
        }
    }

    /* Load and check policy */
    policy_config *policy = policy_load();

    /* Read new password (twice) */
    char newpw[MAX_PASSWORD], newpw2[MAX_PASSWORD];
    if (read_password("New password: ", newpw, sizeof(newpw)) < 0 ||
        read_password("Confirm new password: ", newpw2, sizeof(newpw2)) < 0) {
        fprintf(stderr, "passwd: error reading new password.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    if (strcmp(newpw, newpw2) != 0) {
        fprintf(stderr, "passwd: passwords do not match.\n");
        secure_zero(newpw, sizeof(newpw));
        secure_zero(newpw2, sizeof(newpw2));
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }
    secure_zero(newpw2, sizeof(newpw2));

    /* Enforce complexity policy */
    char errmsg[256];
    if (policy_check_password(policy, newpw, errmsg, sizeof(errmsg)) != 0) {
        fprintf(stderr, "passwd: %s\n", errmsg);
        secure_zero(newpw, sizeof(newpw));
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Hash the new password */
    char *new_hash = hash_password(newpw);
    secure_zero(newpw, sizeof(newpw));
    if (!new_hash) {
        fprintf(stderr, "passwd: hashing failed.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Check password history */
    if (policy_check_history(target_user, new_hash) != 0) {
        fprintf(stderr, "passwd: password was used recently; choose a different one.\n");
        secure_zero(new_hash, strlen(new_hash));
        free(new_hash);
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Update shadow entry */
    policy_add_history(target_user, se->sp_pwdp, policy->history);
    strncpy(se->sp_pwdp, new_hash, MAX_HASH - 1);
    se->sp_lstchg = days_since_epoch();

    secure_zero(new_hash, strlen(new_hash));
    free(new_hash);

    if (shadow_write_all(slist) != 0) {
        fprintf(stderr, "passwd: failed to update password database.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    fprintf(stderr, "passwd: password updated for %s.\n", target_user);
    shadow_free(slist);
    policy_free(policy);
    return 0;
}
