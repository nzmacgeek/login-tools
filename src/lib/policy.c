#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "libauth.h"

/* Default policy values */
#define DEFAULT_MIN_LENGTH        8
#define DEFAULT_MIN_UPPERCASE     1
#define DEFAULT_MIN_LOWERCASE     1
#define DEFAULT_MIN_DIGITS        1
#define DEFAULT_MIN_SPECIAL       1
#define DEFAULT_HISTORY           5
#define DEFAULT_MAX_ATTEMPTS      5
#define DEFAULT_LOCKOUT_TIME      300
#define DEFAULT_LOCKOUT_RESET     900

policy_config *policy_load(void)
{
    policy_config *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return NULL;

    /* Defaults */
    cfg->min_length        = DEFAULT_MIN_LENGTH;
    cfg->min_uppercase     = DEFAULT_MIN_UPPERCASE;
    cfg->min_lowercase     = DEFAULT_MIN_LOWERCASE;
    cfg->min_digits        = DEFAULT_MIN_DIGITS;
    cfg->min_special       = DEFAULT_MIN_SPECIAL;
    cfg->history           = DEFAULT_HISTORY;
    cfg->max_attempts      = DEFAULT_MAX_ATTEMPTS;
    cfg->lockout_time      = DEFAULT_LOCKOUT_TIME;
    cfg->lockout_reset_time= DEFAULT_LOCKOUT_RESET;

    char pf[MAX_PATH];
    FILE *f = fopen(make_path(pf, sizeof(pf), PWPOLICY_FILE), "r");
    if (!f) return cfg; /* use defaults if file missing */

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        size_t l = strlen(line);
        if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';
        /* skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\0') continue;

        char key[64], val[64];
        if (sscanf(line, " %63[^= ] = %63s", key, val) != 2) continue;

#define SETINT(field, name) \
        if (strcmp(key, #name) == 0) { cfg->field = atoi(val); continue; }

        SETINT(min_length,        MIN_LENGTH)
        SETINT(min_uppercase,     MIN_UPPERCASE)
        SETINT(min_lowercase,     MIN_LOWERCASE)
        SETINT(min_digits,        MIN_DIGITS)
        SETINT(min_special,       MIN_SPECIAL)
        SETINT(history,           HISTORY)
        SETINT(max_attempts,      MAX_ATTEMPTS)
        SETINT(lockout_time,      LOCKOUT_TIME)
        SETINT(lockout_reset_time,LOCKOUT_RESET_TIME)
#undef SETINT
    }
    fclose(f);
    return cfg;
}

void policy_free(policy_config *cfg)
{
    free(cfg);
}

int policy_check_password(const policy_config *cfg, const char *password,
                           char *errmsg, size_t errmsg_len)
{
    int upper = 0, lower = 0, digit = 0, special = 0;
    int len = 0;

    for (const char *p = password; *p; p++, len++) {
        unsigned char c = (unsigned char)*p;
        if (isupper(c))        upper++;
        else if (islower(c))   lower++;
        else if (isdigit(c))   digit++;
        else                   special++;
    }

#define FAIL(fmt, ...) do { \
        snprintf(errmsg, errmsg_len, fmt, ##__VA_ARGS__); return -1; \
    } while (0)

    if (len < cfg->min_length)
        FAIL("Password must be at least %d characters long.", cfg->min_length);
    if (upper < cfg->min_uppercase)
        FAIL("Password must contain at least %d uppercase letter(s).", cfg->min_uppercase);
    if (lower < cfg->min_lowercase)
        FAIL("Password must contain at least %d lowercase letter(s).", cfg->min_lowercase);
    if (digit < cfg->min_digits)
        FAIL("Password must contain at least %d digit(s).", cfg->min_digits);
    if (special < cfg->min_special)
        FAIL("Password must contain at least %d special character(s).", cfg->min_special);
#undef FAIL

    return 0;
}

/* Returns 0 if new_hash is NOT in history (password may be reused from policy
 * perspective), -1 if it duplicates a recent password. */
int policy_check_history(const char *username, const char *new_hash)
{
    char of[MAX_PATH];
    FILE *f = fopen(make_path(of, sizeof(of), OPASSWD_FILE), "r");
    if (!f) return 0;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';

        /* format: username:hash1:hash2:... */
        char *save;
        char *user = strtok_r(line, ":", &save);
        if (!user || strcmp(user, username) != 0) continue;

        char *tok;
        while ((tok = strtok_r(NULL, ":", &save)) != NULL) {
            if (strcmp(tok, new_hash) == 0) {
                fclose(f);
                return -1; /* found in history */
            }
        }
        break;
    }
    fclose(f);
    return 0;
}

/* Prepend new_hash to the user's history, trimming to history_depth entries. */
int policy_add_history(const char *username, const char *hash, int history_depth)
{
    /* Read all lines except the user's existing entry */
    char of2[MAX_PATH];
    FILE *f = fopen(make_path(of2, sizeof(of2), OPASSWD_FILE), "r");
    char existing[MAX_HASH * 16] = {0};
    char other[MAX_LINE * 64]    = {0};
    size_t other_len = 0;

    if (f) {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), f)) {
            size_t l = strlen(line);
            if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';
            char tmp[MAX_LINE];
            strncpy(tmp, line, MAX_LINE - 1);
            char *save, *user = strtok_r(tmp, ":", &save);
            if (user && strcmp(user, username) == 0) {
                /* collect existing hashes */
                char *tok;
                while ((tok = strtok_r(NULL, ":", &save)) != NULL) {
                    size_t elen = strlen(existing);
                    if (elen > 0)
                        strncat(existing, ":", sizeof(existing) - elen - 1);
                    elen = strlen(existing);
                    strncat(existing, tok, sizeof(existing) - elen - 1);
                }
            } else {
                size_t ll = strlen(line);
                if (other_len + ll + 2 < sizeof(other)) {
                    memcpy(other + other_len, line, ll);
                    other[other_len + ll] = '\n';
                    other_len += ll + 1;
                }
            }
        }
        fclose(f);
    }

    /* Build new history: new_hash first, then existing, trimmed */
    char new_entry[MAX_HASH * 16];
    snprintf(new_entry, sizeof(new_entry), "%s", hash);
    int count = 1;
    char *save, *tok;
    char existing_copy[sizeof(existing)];
    strncpy(existing_copy, existing, sizeof(existing_copy) - 1);
    for (tok = strtok_r(existing_copy, ":", &save);
         tok && count < history_depth;
         tok = strtok_r(NULL, ":", &save), count++) {
        size_t elen = strlen(new_entry);
        strncat(new_entry, ":", sizeof(new_entry) - elen - 1);
        elen = strlen(new_entry);
        strncat(new_entry, tok, sizeof(new_entry) - elen - 1);
    }

    /* Write out */
    char real_op[MAX_PATH], tmp_path[MAX_PATH];
    make_path(real_op, sizeof(real_op), OPASSWD_FILE);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", real_op, (int)getpid());
    FILE *out = fopen(tmp_path, "w");
    if (!out) return -1;

    if (other_len > 0) fwrite(other, 1, other_len, out);
    fprintf(out, "%s:%s\n", username, new_entry);
    fclose(out);
    rename(tmp_path, real_op);
    return 0;
}
