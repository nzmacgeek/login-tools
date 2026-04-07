#ifndef LIBAUTH_H
#define LIBAUTH_H

#include <sys/types.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * BlueyOS libauth — shared structures and declarations
 * ------------------------------------------------------------------------- */

#define SHADOW_FILE     "/etc/shadow"
#define PASSWD_FILE     "/etc/passwd"
#define GROUP_FILE      "/etc/group"
#define SHELLS_FILE     "/etc/shells"
#define OPASSWD_FILE    "/etc/security/opasswd"
#define PWPOLICY_FILE   "/etc/security/pwpolicy.conf"
#define FAILLOCK_DIR    "/var/run/faillock"

#define MAX_USERNAME    64
#define MAX_PASSWORD    512
#define MAX_HASH        256
#define MAX_GECOS       256
#define MAX_PATH        1024
#define MAX_SHELL       256
#define MAX_LINE        4096
#define MAX_MEMBERS     256
#define MAX_GROUPS      256

/* -------------------------------------------------------------------------
 * /etc/shadow entry
 *
 * Fields:
 *   sp_namp     - username
 *   sp_pwdp     - hashed password ("!" = locked, "*" = no login, "" = no pw)
 *   sp_lstchg   - days since epoch of last change (-1 = unset)
 *   sp_min      - minimum days between changes (-1 = unset)
 *   sp_max      - maximum days before change required (-1 = unset)
 *   sp_warn     - days before expiry to warn (-1 = unset)
 *   sp_inact    - days of inactivity after expiry before disable (-1 = unset)
 *   sp_expire   - absolute expiry date (days since epoch, -1 = unset)
 *   sp_flag     - reserved
 * ------------------------------------------------------------------------- */
typedef struct shadow_entry {
    char   sp_namp[MAX_USERNAME];
    char   sp_pwdp[MAX_HASH];
    long   sp_lstchg;
    long   sp_min;
    long   sp_max;
    long   sp_warn;
    long   sp_inact;
    long   sp_expire;
    unsigned long sp_flag;
    struct shadow_entry *next;
} shadow_entry;

/* -------------------------------------------------------------------------
 * /etc/passwd entry
 * ------------------------------------------------------------------------- */
typedef struct passwd_entry {
    char   pw_name[MAX_USERNAME];
    char   pw_passwd[8];        /* always "x" */
    uid_t  pw_uid;
    gid_t  pw_gid;
    char   pw_gecos[MAX_GECOS];
    char   pw_dir[MAX_PATH];
    char   pw_shell[MAX_SHELL];
    struct passwd_entry *next;
} passwd_entry;

/* -------------------------------------------------------------------------
 * /etc/group entry
 * ------------------------------------------------------------------------- */
typedef struct group_entry {
    char   gr_name[MAX_USERNAME];
    char   gr_passwd[8];        /* usually "x" or "!" */
    gid_t  gr_gid;
    char   gr_mem[MAX_MEMBERS][MAX_USERNAME];
    int    gr_nmem;
    struct group_entry *next;
} group_entry;

/* -------------------------------------------------------------------------
 * Password / lockout policy
 * ------------------------------------------------------------------------- */
typedef struct policy_config {
    int min_length;
    int min_uppercase;
    int min_lowercase;
    int min_digits;
    int min_special;
    int history;
    int max_attempts;
    int lockout_time;        /* seconds */
    int lockout_reset_time;  /* seconds */
} policy_config;

/* -------------------------------------------------------------------------
 * shadow.c
 * ------------------------------------------------------------------------- */
shadow_entry *shadow_read_all(void);
shadow_entry *shadow_find(shadow_entry *list, const char *username);
int           shadow_write_all(shadow_entry *list);
void          shadow_free(shadow_entry *list);
long          days_since_epoch(void);

/* -------------------------------------------------------------------------
 * passwd_file.c
 * ------------------------------------------------------------------------- */
passwd_entry *passwd_read_all(void);
passwd_entry *passwd_find(passwd_entry *list, const char *username);
passwd_entry *passwd_find_uid(passwd_entry *list, uid_t uid);
int           passwd_write_all(passwd_entry *list);
void          passwd_free(passwd_entry *list);
uid_t         passwd_next_uid(passwd_entry *list, uid_t min_uid);

/* -------------------------------------------------------------------------
 * group_file.c
 * ------------------------------------------------------------------------- */
group_entry *group_read_all(void);
group_entry *group_find(group_entry *list, const char *name);
group_entry *group_find_gid(group_entry *list, gid_t gid);
int          group_write_all(group_entry *list);
void         group_free(group_entry *list);
gid_t        group_next_gid(group_entry *list, gid_t min_gid);
int          group_has_member(group_entry *grp, const char *username);
int          group_add_member(group_entry *grp, const char *username);
int          group_remove_member(group_entry *grp, const char *username);

/* -------------------------------------------------------------------------
 * policy.c
 * ------------------------------------------------------------------------- */
policy_config *policy_load(void);
void           policy_free(policy_config *cfg);
int            policy_check_password(const policy_config *cfg,
                                     const char *password,
                                     char *errmsg, size_t errmsg_len);
int            policy_check_history(const char *username, const char *new_hash);
int            policy_add_history(const char *username, const char *hash,
                                  int history_depth);

/* -------------------------------------------------------------------------
 * faillock.c
 * ------------------------------------------------------------------------- */
int faillock_check(const char *username, int max_attempts, int lockout_time,
                   int reset_time);
int faillock_increment(const char *username);
int faillock_reset(const char *username);

/* -------------------------------------------------------------------------
 * util.c
 * ------------------------------------------------------------------------- */
char *hash_password(const char *password);
int   verify_password(const char *password, const char *hash);
int   read_password(const char *prompt, char *buf, size_t buflen);
void  secure_zero(void *ptr, size_t len);
int   is_valid_username(const char *name);
int   shell_is_valid(const char *shell);
int   ensure_dir(const char *path, mode_t mode);

/* Sysroot support — call set_sysroot() once at startup to redirect all file
 * operations to a different root (e.g. an offline BlueyOS image).
 * make_path() builds "<sysroot><rel>" into buf and returns buf. */
void  set_sysroot(const char *path);
char *make_path(char *buf, size_t buflen, const char *rel);

#endif /* LIBAUTH_H */
