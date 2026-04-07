#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "libauth.h"

/* Per-user faillock file: FAILLOCK_DIR/<username>
 * Contents: two lines
 *   count=<n>
 *   last=<unix_timestamp>
 */

static void faillock_path(char *buf, size_t len, const char *username)
{
    char dir[MAX_PATH];
    make_path(dir, sizeof(dir), FAILLOCK_DIR);
    snprintf(buf, len, "%s/%s", dir, username);
}

/* Returns 1 if the account is currently locked, 0 if not. */
int faillock_check(const char *username, int max_attempts, int lockout_time,
                   int reset_time)
{
    char path[MAX_PATH];
    faillock_path(path, sizeof(path), username);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int count = 0;
    long last = 0;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "count=", 6) == 0)
            count = atoi(line + 6);
        else if (strncmp(line, "last=", 5) == 0)
            last = strtol(line + 5, NULL, 10);
    }
    fclose(f);

    time_t now = time(NULL);

    /* If the last failure was more than reset_time ago, not locked */
    if (reset_time > 0 && (long)now - last > reset_time) return 0;

    /* If under the threshold, not locked */
    if (count < max_attempts) return 0;

    /* If lockout_time has elapsed since last failure, not locked */
    if (lockout_time > 0 && (long)now - last >= lockout_time) return 0;

    return 1;
}

int faillock_increment(const char *username)
{
    /* Ensure directory exists */
    char fldir[MAX_PATH];
    make_path(fldir, sizeof(fldir), FAILLOCK_DIR);
    if (ensure_dir(fldir, 0750) < 0) return -1;

    char path[MAX_PATH];
    faillock_path(path, sizeof(path), username);

    int count = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        char line[64];
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "count=", 6) == 0)
                count = atoi(line + 6);
        fclose(f);
    }
    count++;

    f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "count=%d\nlast=%ld\n", count, (long)time(NULL));
    fclose(f);
    return 0;
}

int faillock_reset(const char *username)
{
    char path[MAX_PATH];
    faillock_path(path, sizeof(path), username);
    /* Unlink the file — clean slate */
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}
