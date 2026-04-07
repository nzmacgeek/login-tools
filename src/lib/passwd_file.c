#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "libauth.h"

static passwd_entry *parse_passwd_line(const char *line)
{
    char buf[MAX_LINE];
    strncpy(buf, line, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    if (buf[0] == '\0' || buf[0] == '#') return NULL;

    passwd_entry *e = calloc(1, sizeof(*e));
    if (!e) return NULL;

    char *tok, *save;
    tok = strtok_r(buf, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->pw_name, tok, MAX_USERNAME - 1);

    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->pw_passwd, tok, sizeof(e->pw_passwd) - 1);

    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    e->pw_uid = (uid_t)strtoul(tok, NULL, 10);

    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    e->pw_gid = (gid_t)strtoul(tok, NULL, 10);

    tok = strtok_r(NULL, ":", &save);
    if (tok) strncpy(e->pw_gecos, tok, MAX_GECOS - 1);

    tok = strtok_r(NULL, ":", &save);
    if (tok) strncpy(e->pw_dir, tok, MAX_PATH - 1);

    tok = strtok_r(NULL, ":", &save);
    if (tok) strncpy(e->pw_shell, tok, MAX_SHELL - 1);

    return e;
}

passwd_entry *passwd_read_all(void)
{
    char pf[MAX_PATH];
    FILE *f = fopen(make_path(pf, sizeof(pf), PASSWD_FILE), "r");
    if (!f) return NULL;
    flock(fileno(f), LOCK_SH);

    passwd_entry *head = NULL, *tail = NULL;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        passwd_entry *e = parse_passwd_line(line);
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

passwd_entry *passwd_find(passwd_entry *list, const char *username)
{
    for (passwd_entry *e = list; e; e = e->next)
        if (strcmp(e->pw_name, username) == 0) return e;
    return NULL;
}

passwd_entry *passwd_find_uid(passwd_entry *list, uid_t uid)
{
    for (passwd_entry *e = list; e; e = e->next)
        if (e->pw_uid == uid) return e;
    return NULL;
}

int passwd_write_all(passwd_entry *list)
{
    char real[MAX_PATH], tmp[MAX_PATH];
    make_path(real, sizeof(real), PASSWD_FILE);
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", real, (int)getpid());

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open passwd tmp"); return -1; }
    flock(fd, LOCK_EX);

    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }

    for (passwd_entry *e = list; e; e = e->next) {
        fprintf(f, "%s:%s:%u:%u:%s:%s:%s\n",
                e->pw_name, e->pw_passwd,
                (unsigned)e->pw_uid, (unsigned)e->pw_gid,
                e->pw_gecos, e->pw_dir, e->pw_shell);
    }

    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);

    if (rename(tmp, real) != 0) {
        perror("rename passwd");
        unlink(tmp);
        return -1;
    }
    return 0;
}

void passwd_free(passwd_entry *list)
{
    while (list) {
        passwd_entry *next = list->next;
        free(list);
        list = next;
    }
}

uid_t passwd_next_uid(passwd_entry *list, uid_t min_uid)
{
    uid_t candidate = min_uid;
    int found;
    do {
        found = 0;
        for (passwd_entry *e = list; e; e = e->next) {
            if (e->pw_uid == candidate) { found = 1; break; }
        }
        if (found) candidate++;
    } while (found);
    return candidate;
}
