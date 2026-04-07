#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include "libauth.h"

long days_since_epoch(void)
{
    return (long)(time(NULL) / 86400);
}

/* Parse a single shadow line (colon-separated) into a heap-allocated entry.
 * Returns NULL on parse error. The caller owns the result. */
static shadow_entry *parse_shadow_line(const char *line)
{
    char buf[MAX_LINE];
    strncpy(buf, line, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    if (buf[0] == '\0' || buf[0] == '#') return NULL;

    shadow_entry *e = calloc(1, sizeof(*e));
    if (!e) return NULL;

    char *tok, *save;
    /* field 1: username */
    tok = strtok_r(buf, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->sp_namp, tok, MAX_USERNAME - 1);

    /* field 2: password hash */
    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->sp_pwdp, tok, MAX_HASH - 1);

#define PARSE_LONG(field, def) \
    tok = strtok_r(NULL, ":", &save); \
    (field) = (tok && *tok) ? strtol(tok, NULL, 10) : (def);

    PARSE_LONG(e->sp_lstchg, -1)
    PARSE_LONG(e->sp_min,    -1)
    PARSE_LONG(e->sp_max,    -1)
    PARSE_LONG(e->sp_warn,   -1)
    PARSE_LONG(e->sp_inact,  -1)
    PARSE_LONG(e->sp_expire, -1)
    tok = strtok_r(NULL, ":", &save);
    e->sp_flag = (tok && *tok) ? strtoul(tok, NULL, 10) : 0;
#undef PARSE_LONG

    return e;
}

shadow_entry *shadow_read_all(void)
{
    char sf[MAX_PATH];
    FILE *f = fopen(make_path(sf, sizeof(sf), SHADOW_FILE), "r");
    if (!f) return NULL;
    flock(fileno(f), LOCK_SH);

    shadow_entry *head = NULL, *tail = NULL;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        shadow_entry *e = parse_shadow_line(line);
        if (!e) continue;
        e->next = NULL;
        if (!head) head = e;
        else        tail->next = e;
        tail = e;
    }

    flock(fileno(f), LOCK_UN);
    fclose(f);
    return head;
}

shadow_entry *shadow_find(shadow_entry *list, const char *username)
{
    for (shadow_entry *e = list; e; e = e->next)
        if (strcmp(e->sp_namp, username) == 0) return e;
    return NULL;
}

/* Atomic write: write to a temp file then rename over the original */
int shadow_write_all(shadow_entry *list)
{
    char real[MAX_PATH], tmp[MAX_PATH];
    make_path(real, sizeof(real), SHADOW_FILE);
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", real, (int)getpid());

    /* Shadow file must be root-owned, mode 0640 */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) { perror("open shadow tmp"); return -1; }
    flock(fd, LOCK_EX);

    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }

    for (shadow_entry *e = list; e; e = e->next) {
        /* Format: name:hash:lstchg:min:max:warn:inact:expire:flag */
        fprintf(f, "%s:%s:", e->sp_namp, e->sp_pwdp);
        if (e->sp_lstchg >= 0) { fprintf(f, "%ld", e->sp_lstchg); } fputc(':', f);
        if (e->sp_min    >= 0) { fprintf(f, "%ld", e->sp_min);    } fputc(':', f);
        if (e->sp_max    >= 0) { fprintf(f, "%ld", e->sp_max);    } fputc(':', f);
        if (e->sp_warn   >= 0) { fprintf(f, "%ld", e->sp_warn);   } fputc(':', f);
        if (e->sp_inact  >= 0) { fprintf(f, "%ld", e->sp_inact);  } fputc(':', f);
        if (e->sp_expire >= 0) { fprintf(f, "%ld", e->sp_expire); } fputc(':', f);
        if (e->sp_flag)        fprintf(f, "%lu", e->sp_flag);
        fputc('\n', f);
    }

    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);

    if (rename(tmp, real) != 0) {
        perror("rename shadow");
        unlink(tmp);
        return -1;
    }
    return 0;
}

void shadow_free(shadow_entry *list)
{
    while (list) {
        shadow_entry *next = list->next;
        secure_zero(list->sp_pwdp, sizeof(list->sp_pwdp));
        free(list);
        list = next;
    }
}
