#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "libauth.h"

static group_entry *parse_group_line(const char *line)
{
    char buf[MAX_LINE];
    strncpy(buf, line, MAX_LINE - 1);
    buf[MAX_LINE - 1] = '\0';

    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    if (buf[0] == '\0' || buf[0] == '#') return NULL;

    group_entry *e = calloc(1, sizeof(*e));
    if (!e) return NULL;

    char *tok, *save;
    tok = strtok_r(buf, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->gr_name, tok, MAX_USERNAME - 1);

    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    strncpy(e->gr_passwd, tok, sizeof(e->gr_passwd) - 1);

    tok = strtok_r(NULL, ":", &save);
    if (!tok) { free(e); return NULL; }
    e->gr_gid = (gid_t)strtoul(tok, NULL, 10);

    /* member list: comma-separated */
    tok = strtok_r(NULL, ":", &save);
    e->gr_nmem = 0;
    if (tok && *tok) {
        char *mtok, *msave;
        for (mtok = strtok_r(tok, ",", &msave);
             mtok && e->gr_nmem < MAX_MEMBERS;
             mtok = strtok_r(NULL, ",", &msave)) {
            strncpy(e->gr_mem[e->gr_nmem++], mtok, MAX_USERNAME - 1);
        }
    }
    return e;
}

group_entry *group_read_all(void)
{
    char gf[MAX_PATH];
    FILE *f = fopen(make_path(gf, sizeof(gf), GROUP_FILE), "r");
    if (!f) return NULL;
    flock(fileno(f), LOCK_SH);

    group_entry *head = NULL, *tail = NULL;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        group_entry *e = parse_group_line(line);
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

group_entry *group_find(group_entry *list, const char *name)
{
    for (group_entry *e = list; e; e = e->next)
        if (strcmp(e->gr_name, name) == 0) return e;
    return NULL;
}

group_entry *group_find_gid(group_entry *list, gid_t gid)
{
    for (group_entry *e = list; e; e = e->next)
        if (e->gr_gid == gid) return e;
    return NULL;
}

int group_write_all(group_entry *list)
{
    char real[MAX_PATH], tmp[MAX_PATH];
    make_path(real, sizeof(real), GROUP_FILE);
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", real, (int)getpid());

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open group tmp"); return -1; }
    flock(fd, LOCK_EX);

    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }

    for (group_entry *e = list; e; e = e->next) {
        fprintf(f, "%s:%s:%u:", e->gr_name, e->gr_passwd, (unsigned)e->gr_gid);
        for (int i = 0; i < e->gr_nmem; i++) {
            if (i > 0) fputc(',', f);
            fputs(e->gr_mem[i], f);
        }
        fputc('\n', f);
    }

    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);

    if (rename(tmp, real) != 0) {
        perror("rename group");
        unlink(tmp);
        return -1;
    }
    return 0;
}

void group_free(group_entry *list)
{
    while (list) {
        group_entry *next = list->next;
        free(list);
        list = next;
    }
}

gid_t group_next_gid(group_entry *list, gid_t min_gid)
{
    gid_t candidate = min_gid;
    int found;
    do {
        found = 0;
        for (group_entry *e = list; e; e = e->next) {
            if (e->gr_gid == candidate) { found = 1; break; }
        }
        if (found) candidate++;
    } while (found);
    return candidate;
}

int group_has_member(group_entry *grp, const char *username)
{
    for (int i = 0; i < grp->gr_nmem; i++)
        if (strcmp(grp->gr_mem[i], username) == 0) return 1;
    return 0;
}

int group_add_member(group_entry *grp, const char *username)
{
    if (group_has_member(grp, username)) return 0;
    if (grp->gr_nmem >= MAX_MEMBERS) return -1;
    strncpy(grp->gr_mem[grp->gr_nmem++], username, MAX_USERNAME - 1);
    return 0;
}

int group_remove_member(group_entry *grp, const char *username)
{
    for (int i = 0; i < grp->gr_nmem; i++) {
        if (strcmp(grp->gr_mem[i], username) == 0) {
            /* shift remaining members left */
            for (int j = i; j < grp->gr_nmem - 1; j++)
                memcpy(grp->gr_mem[j], grp->gr_mem[j+1], MAX_USERNAME);
            grp->gr_nmem--;
            return 0;
        }
    }
    return -1; /* not found */
}
