#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <crypt.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include "libauth.h"

/* Generate a random base64-encoded salt string for SHA-512 crypt */
static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

char *hash_password(const char *password)
{
    /* Build a $6$<16-char salt>$ prefix */
    unsigned char raw[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        return NULL;
    }
    if (read(fd, raw, sizeof(raw)) != (ssize_t)sizeof(raw)) {
        close(fd);
        perror("read /dev/urandom");
        return NULL;
    }
    close(fd);

    char salt[32];
    snprintf(salt, sizeof(salt), "$6$");
    for (int i = 0; i < 16; i++)
        salt[3 + i] = b64[raw[i] & 0x3f];
    salt[19] = '$';
    salt[20] = '\0';

    struct crypt_data cd;
    memset(&cd, 0, sizeof(cd));
    char *result = crypt_r(password, salt, &cd);
    if (!result) {
        perror("crypt_r");
        return NULL;
    }

    char *copy = strdup(result);
    secure_zero(&cd, sizeof(cd));
    return copy;
}

int verify_password(const char *password, const char *hash)
{
    if (!hash || !password)
        return 0;
    /* Locked account or no-login marker */
    if (hash[0] == '!' || hash[0] == '*')
        return 0;
    /* Empty password: only matches empty input */
    if (hash[0] == '\0')
        return (password[0] == '\0');

    struct crypt_data cd;
    memset(&cd, 0, sizeof(cd));
    char *result = crypt_r(password, hash, &cd);
    int ok = (result && strcmp(result, hash) == 0);
    secure_zero(&cd, sizeof(cd));
    return ok;
}

/* Read a password from the terminal without echo.
 * Returns 0 on success, -1 on error. */
int read_password(const char *prompt, char *buf, size_t buflen)
{
    struct termios old, noecho;
    int tty = open("/dev/tty", O_RDWR);
    if (tty < 0) tty = STDIN_FILENO;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if (tcgetattr(tty, &old) == 0) {
        noecho = old;
        noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(tty, TCSANOW, &noecho);
    }

    FILE *ttyf = (tty == STDIN_FILENO) ? stdin : fdopen(tty, "r+");
    char *line = fgets(buf, (int)buflen, ttyf ? ttyf : stdin);

    if (tcgetattr(tty, &old) == 0) {
        /* restore — old already has echo */
        old.c_lflag |= ECHO;
        tcsetattr(tty, TCSANOW, &old);
    }
    fprintf(stderr, "\n");

    if (ttyf && tty != STDIN_FILENO) fclose(ttyf);

    if (!line) return -1;

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

int is_valid_username(const char *name)
{
    if (!name || !*name) return 0;
    /* POSIX portable character set: [a-zA-Z0-9._-], must not start with '-' */
    if (name[0] == '-') return 0;
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) &&
            *p != '_' && *p != '-' && *p != '.') return 0;
    }
    return strlen(name) <= 32;
}

/* -------------------------------------------------------------------------
 * Sysroot support
 * ------------------------------------------------------------------------- */

static char g_sysroot[MAX_PATH] = {0};

void set_sysroot(const char *path)
{
    if (path && *path) {
        strncpy(g_sysroot, path, MAX_PATH - 1);
        g_sysroot[MAX_PATH - 1] = '\0';
        /* Strip trailing slash(es), except a lone "/" root */
        size_t l = strlen(g_sysroot);
        while (l > 1 && g_sysroot[l - 1] == '/')
            g_sysroot[--l] = '\0';
    } else {
        g_sysroot[0] = '\0';
    }
}

char *make_path(char *buf, size_t buflen, const char *rel)
{
    if (g_sysroot[0])
        snprintf(buf, buflen, "%s%s", g_sysroot, rel);
    else
        snprintf(buf, buflen, "%s", rel);
    return buf;
}

int shell_is_valid(const char *shell)
{
    char sf[MAX_PATH];
    FILE *f = fopen(make_path(sf, sizeof(sf), SHELLS_FILE), "r");
    if (!f) return 1; /* no /etc/shells — allow anything */
    char line[MAX_SHELL];
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        if (strcmp(line, shell) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(path, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}
