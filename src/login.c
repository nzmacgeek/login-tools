#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include "lib/libauth.h"

/*
 * login — authenticate and start a user session
 *
 * Usage:
 *   login [--matey-handoff] [username]
 *
 * Default behavior: authenticate, drop to the user's uid/gid, set login
 * environment, chdir to HOME, then exec the user's shell from /etc/passwd.
 *
 * Compatibility mode: --matey-handoff prints the authenticated username on
 * stdout and exits 0, matching matey's legacy handoff contract.
 */

#define DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define LOGIN_DEF_MAX_ATTEMPTS 5
#define LOGIN_DEF_LOCKOUT_TIME 300
#define LOGIN_DEF_LOCKOUT_RESET 900

static void start_session_or_die(const passwd_entry *pe)
{
    const char *home = (pe->pw_dir[0] != '\0') ? pe->pw_dir : "/";
    const char *shell = (pe->pw_shell[0] != '\0') ? pe->pw_shell : "/bin/sh";

    if (!shell_is_valid(shell))
        shell = "/bin/sh";

    if (geteuid() == 0) {
        /* Supplementary groups are best-effort here; some minimal kernels may
         * not implement setgroups yet. Continue with primary gid/uid drop. */
        if (setgroups(0, NULL) != 0) {
            fprintf(stderr, "login: warning: setgroups failed: %s\n", strerror(errno));
        }
        if (setgid(pe->pw_gid) != 0) {
            fprintf(stderr, "login: failed to setgid(%u): %s\n", (unsigned)pe->pw_gid, strerror(errno));
            exit(1);
        }
        if (setuid(pe->pw_uid) != 0) {
            fprintf(stderr, "login: failed to setuid(%u): %s\n", (unsigned)pe->pw_uid, strerror(errno));
            exit(1);
        }
    }

    const char *old_term = getenv("TERM");

    char home_env[MAX_PATH + 5];
    char shell_env[MAX_SHELL + 6];
    char user_env[MAX_USERNAME + 6];
    char logname_env[MAX_USERNAME + 9];
    char path_env[sizeof("PATH=") + sizeof(DEFAULT_PATH)];
    char term_env[sizeof("TERM=") + 128];

    snprintf(home_env, sizeof(home_env), "HOME=%s", home);
    snprintf(shell_env, sizeof(shell_env), "SHELL=%s", shell);
    snprintf(user_env, sizeof(user_env), "USER=%s", pe->pw_name);
    snprintf(logname_env, sizeof(logname_env), "LOGNAME=%s", pe->pw_name);
    snprintf(path_env, sizeof(path_env), "PATH=%s", DEFAULT_PATH);

    if (chdir(home) != 0) {
        if (chdir("/") != 0) {
            fprintf(stderr, "login: failed to chdir to '%s' and '/': %s\n", home, strerror(errno));
            exit(1);
        }
    }

    const char *base = strrchr(shell, '/');
    base = base ? base + 1 : shell;

    char login_argv0[MAX_SHELL + 2];
    snprintf(login_argv0, sizeof(login_argv0), "-%s", base);

    char *const sh_argv[] = { login_argv0, NULL };
    char *envp[7];
    int envc = 0;

    envp[envc++] = home_env;
    envp[envc++] = shell_env;
    envp[envc++] = user_env;
    envp[envc++] = logname_env;
    envp[envc++] = path_env;
    if (old_term && *old_term) {
        snprintf(term_env, sizeof(term_env), "TERM=%s", old_term);
        envp[envc++] = term_env;
    }
    envp[envc] = NULL;

    execve(shell, sh_argv, envp);

    fprintf(stderr, "login: cannot exec '%s': %s\n", shell, strerror(errno));
    exit(1);
}

int main(int argc, char *argv[])
{
    char username[MAX_USERNAME] = {0};
    const char *username_arg = NULL;
    int matey_handoff = 0;

    const char *sysroot = getenv("BLUEYOS_ROOT");
    if (sysroot && *sysroot)
        set_sysroot(sysroot);

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--matey-handoff") == 0) {
            matey_handoff = 1;
            continue;
        }
        if (strcmp(argv[index], "-p") == 0) {
            continue;
        }
        if (strcmp(argv[index], "--") == 0) {
            if (index + 1 < argc) {
                username_arg = argv[index + 1];
            }
            break;
        }
        username_arg = argv[index];
        break;
    }

    if (username_arg) {
        strncpy(username, username_arg, MAX_USERNAME - 1);
    } else {
        printf("Username: ");
        fflush(stdout);
        if (!fgets(username, sizeof(username), stdin)) {
            fprintf(stderr, "login: error reading username.\n");
            exit(1);
        }
        size_t l = strlen(username);
        if (l > 0 && username[l-1] == '\n') username[l-1] = '\0';
    }

    if (!is_valid_username(username)) {
        fprintf(stderr, "login: invalid username.\n");
        exit(1);
    }

    /* Check /etc/passwd exists */
    passwd_entry *plist = passwd_read_all();
    passwd_entry *pe = passwd_find(plist, username);
    if (!pe) {
        /* Don't reveal whether user exists — still ask for password */
        char dummy[MAX_PASSWORD];
        read_password("Password: ", dummy, sizeof(dummy));
        secure_zero(dummy, sizeof(dummy));
        fprintf(stderr, "login: authentication failure.\n");
        passwd_free(plist);
        exit(1);
    }

    /* Check faillock */
    if (faillock_check(username, LOGIN_DEF_MAX_ATTEMPTS,
                        LOGIN_DEF_LOCKOUT_TIME, LOGIN_DEF_LOCKOUT_RESET)) {
        fprintf(stderr, "login: account locked due to too many failed attempts.\n");
        passwd_free(plist);
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
        passwd_free(plist);
        exit(1);
    }

    /* Check locked / no-login marker */
    if (se->sp_pwdp[0] == '!' || se->sp_pwdp[0] == '*') {
        char dummy[MAX_PASSWORD];
        read_password("Password: ", dummy, sizeof(dummy));
        secure_zero(dummy, sizeof(dummy));
        fprintf(stderr, "login: account is locked.\n");
        shadow_free(slist);
        passwd_free(plist);
        exit(1);
    }

    /* Check account expiry */
    if (se->sp_expire >= 0 && days_since_epoch() > se->sp_expire) {
        fprintf(stderr, "login: account has expired.\n");
        shadow_free(slist);
        passwd_free(plist);
        exit(1);
    }

    /* Read password */
    char password[MAX_PASSWORD];
    if (read_password("Password: ", password, sizeof(password)) < 0) {
        fprintf(stderr, "login: error reading password.\n");
        shadow_free(slist);
        passwd_free(plist);
        exit(1);
    }

    int ok = verify_password(password, se->sp_pwdp);
    secure_zero(password, sizeof(password));

    if (!ok) {
        faillock_increment(username);
        /* Re-check if now locked */
        if (faillock_check(username, LOGIN_DEF_MAX_ATTEMPTS,
                            LOGIN_DEF_LOCKOUT_TIME, LOGIN_DEF_LOCKOUT_RESET)) {
            fprintf(stderr, "login: account locked due to too many failed attempts.\n");
        } else {
            fprintf(stderr, "login: authentication failure.\n");
        }
        shadow_free(slist);
        passwd_free(plist);
        exit(1);
    }

    /* Success */
    faillock_reset(username);
    shadow_free(slist);

    if (matey_handoff) {
        /* Legacy contract used by matey login handoff. */
        printf("%s\n", username);
        passwd_free(plist);
        return 0;
    }

    start_session_or_die(pe);
    passwd_free(plist);
    return 1;
}
