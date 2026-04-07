#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/libauth.h"

/*
 * setup-root — set the root password for the first time
 *
 * Usage:
 *   setup-root                        live system  (must run as root)
 *   setup-root --sysroot /mnt/image   offline provision into a mounted sysroot
 *
 * Refuses to run if root already has a real password in /etc/shadow
 * (i.e., something other than "", "!", or "*").
 */

static void usage(void)
{
    fprintf(stderr, "usage: setup-root [--sysroot <path>]\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *sysroot = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sysroot") == 0) {
            if (++i >= argc) usage();
            sysroot = argv[i];
        } else {
            usage();
        }
    }

    /* For live-system use we must be root.
     * For offline provisioning the caller must have write access to the
     * sysroot — no uid check needed beyond normal filesystem permissions. */
    if (!sysroot && getuid() != 0) {
        fprintf(stderr, "setup-root: must be run as root (or use --sysroot for offline use).\n");
        exit(1);
    }

    if (sysroot)
        set_sysroot(sysroot);

    shadow_entry *slist = shadow_read_all();
    shadow_entry *se = shadow_find(slist, "root");

    if (se) {
        const char *pw = se->sp_pwdp;
        /* If root already has a real password, refuse */
        if (pw[0] != '\0' && pw[0] != '!' && pw[0] != '*') {
            fprintf(stderr,
                    "setup-root: root password is already set.\n"
                    "            Use passwd to change it.\n");
            shadow_free(slist);
            exit(1);
        }
    }

    /* Root entry may not exist yet if this is a fresh install */
    policy_config *policy = policy_load();

    char pw1[MAX_PASSWORD], pw2[MAX_PASSWORD];
    if (read_password("New root password: ", pw1, sizeof(pw1)) < 0 ||
        read_password("Confirm root password: ", pw2, sizeof(pw2)) < 0) {
        fprintf(stderr, "setup-root: error reading password.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    if (strcmp(pw1, pw2) != 0) {
        fprintf(stderr, "setup-root: passwords do not match.\n");
        secure_zero(pw1, sizeof(pw1));
        secure_zero(pw2, sizeof(pw2));
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }
    secure_zero(pw2, sizeof(pw2));

    char errmsg[256];
    if (policy_check_password(policy, pw1, errmsg, sizeof(errmsg)) != 0) {
        fprintf(stderr, "setup-root: %s\n", errmsg);
        secure_zero(pw1, sizeof(pw1));
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    char *new_hash = hash_password(pw1);
    secure_zero(pw1, sizeof(pw1));
    if (!new_hash) {
        fprintf(stderr, "setup-root: hashing failed.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    if (se) {
        strncpy(se->sp_pwdp, new_hash, MAX_HASH - 1);
        se->sp_lstchg = days_since_epoch();
    } else {
        /* Create a new root entry and prepend to the list */
        shadow_entry *ne = calloc(1, sizeof(*ne));
        strncpy(ne->sp_namp, "root", MAX_USERNAME - 1);
        strncpy(ne->sp_pwdp, new_hash, MAX_HASH - 1);
        ne->sp_lstchg = days_since_epoch();
        ne->sp_min    = -1;
        ne->sp_max    = -1;
        ne->sp_warn   = -1;
        ne->sp_inact  = -1;
        ne->sp_expire = -1;
        ne->next      = slist;
        slist         = ne;
    }

    secure_zero(new_hash, strlen(new_hash));
    free(new_hash);

    if (shadow_write_all(slist) != 0) {
        fprintf(stderr, "setup-root: failed to write password database.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    if (sysroot)
        fprintf(stderr, "setup-root: root password set in %s.\n", sysroot);
    else
        fprintf(stderr, "setup-root: root password set successfully.\n");

    shadow_free(slist);
    policy_free(policy);
    return 0;
}

