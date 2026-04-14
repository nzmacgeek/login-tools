#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>

/*
 * chmod — change file mode bits
 *
 * Usage: chmod [-R] [-v] [-c] MODE FILE...
 *   -R  apply recursively
 *   -v  verbose: show each file processed
 *   -c  report only when a change is made
 *
 * MODE may be an octal number (e.g. 755) or a symbolic expression
 * (e.g. u+x, a=rw, go-w).
 */

static int flag_recursive = 0;
static int flag_verbose   = 0;
static int flag_changes   = 0;

/* ---- symbolic mode parser ------------------------------------------------ */

/* Return the 3-slot mask for a who character ('u','g','o','a') or -1. */
static int who_mask(char c)
{
    switch (c) {
    case 'u': return 0700;
    case 'g': return 0070;
    case 'o': return 0007;
    case 'a': return 0777;
    default:  return -1;
    }
}

/* Apply one symbolic clause (e.g. "u+x", "go-w", "a=rw", "u+s") to *mode.
 * Returns 0 on success, -1 on parse error. */
static int apply_clause(mode_t *mode, const char *clause)
{
    const char *p = clause;
    int who = 0;

    while (*p && who_mask(*p) >= 0) {
        who |= who_mask(*p);
        p++;
    }
    if (who == 0)
        who = 0777; /* default: all */

    if (!*p || (*p != '+' && *p != '-' && *p != '='))
        return -1;

    char op = *p++;

    /* Regular rwx bits spread across all three slots */
    int perms = 0;
    /* Special bits (SUID, SGID, SVTX) collected separately — they are
     * outside the 0777 mask and must be handled independently. */
    int specials = 0;

    while (*p) {
        if (*p == 'r') {
            perms |= 0444;
        } else if (*p == 'w') {
            perms |= 0222;
        } else if (*p == 'x') {
            perms |= 0111;
        } else if (*p == 'X') {
            /* Conditional execute: set only if target is a directory
             * or already has at least one execute bit set. */
            if (S_ISDIR(*mode) || (*mode & 0111))
                perms |= 0111;
        } else if (*p == 's') {
            specials |= (int)(S_ISUID | S_ISGID);
        } else if (*p == 't') {
            specials |= (int)S_ISVTX;
        } else {
            /* Reference: copy bits from u/g/o source */
            int src = who_mask(*p);
            if (src < 0)
                return -1;
            mode_t src_bits = *mode & (mode_t)src;
            int shift = 0;
            if (src == 0700)      shift = 6;
            else if (src == 0070) shift = 3;
            perms |= (int)((src_bits >> shift) & 7) * 0111;
        }
        p++;
    }

    /* Map 'who' slots to the corresponding special bits:
     *   u (0700) → SUID,  g (0070) → SGID,  o (0007) → SVTX */
    int special_who = 0;
    if (who & 0700) special_who |= (int)S_ISUID;
    if (who & 0070) special_who |= (int)S_ISGID;
    if (who & 0007) special_who |= (int)S_ISVTX;
    int special_masked = specials & special_who;

    int masked = perms & who;
    switch (op) {
    case '+':
        *mode |= (mode_t)masked | (mode_t)special_masked;
        break;
    case '-':
        *mode &= ~((mode_t)masked | (mode_t)special_masked);
        break;
    case '=':
        *mode = (*mode & ~((mode_t)who | (mode_t)special_who)) |
                (mode_t)masked | (mode_t)special_masked;
        break;
    }
    return 0;
}

/* Apply a comma-separated symbolic mode string.  Returns 0 or -1. */
static int parse_symbolic(const char *spec, mode_t *mode)
{
    char buf[256];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *save, *tok;
    for (tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (apply_clause(mode, tok) != 0)
            return -1;
    }
    return 0;
}

/* Attempt to parse an octal mode; returns (mode_t)-1 on failure. */
static mode_t try_octal(const char *s)
{
    if (!*s) return (mode_t)-1;
    char *end;
    long val = strtol(s, &end, 8);
    if (*end != '\0' || val < 0 || val > 07777)
        return (mode_t)-1;
    return (mode_t)val;
}

/* ---- core operation ------------------------------------------------------ */

static int do_chmod(const char *path, const char *mode_str)
{
    mode_t octal = try_octal(mode_str);

    /* Fast path: pure octal mode, no feedback needed.
     * A single chmod() call avoids any TOCTOU window. */
    if (octal != (mode_t)-1 && !flag_verbose && !flag_changes) {
        if (chmod(path, octal) != 0) {
            fprintf(stderr, "chmod: changing permissions of '%s': %s\n",
                    path, strerror(errno));
            return 1;
        }
        return 0;
    }

    /* For symbolic modes or verbose output, prefer operating on a file
     * descriptor so that fstat() and fchmod() reference the same inode,
     * eliminating the TOCTOU window between the stat and the chmod.
     *
     * However, opening read-only can fail with EACCES even when the caller is
     * still permitted to chmod the file (owner can chmod without read access).
     * In that case, fall back to path-based stat()/chmod() to preserve
     * standard chmod semantics. */
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    struct stat st;
    mode_t old_mode;
    mode_t new_mode;

    if (fd >= 0) {
        if (fstat(fd, &st) != 0) {
            fprintf(stderr, "chmod: cannot stat '%s': %s\n", path, strerror(errno));
            close(fd);
            return 1;
        }

        old_mode = st.st_mode & 07777;
        new_mode = (octal != (mode_t)-1) ? octal : old_mode;

        if (octal == (mode_t)-1) {
            if (parse_symbolic(mode_str, &new_mode) != 0) {
                fprintf(stderr, "chmod: invalid mode: '%s'\n", mode_str);
                close(fd);
                return 1;
            }
        }

        if (fchmod(fd, new_mode) != 0) {
            fprintf(stderr, "chmod: changing permissions of '%s': %s\n",
                    path, strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
    } else {
        if (errno != EACCES) {
            fprintf(stderr, "chmod: cannot open '%s': %s\n", path, strerror(errno));
            return 1;
        }

        /* EACCES fallback: use path-based stat + chmod */
        if (stat(path, &st) != 0) {
            fprintf(stderr, "chmod: cannot stat '%s': %s\n", path, strerror(errno));
            return 1;
        }

        old_mode = st.st_mode & 07777;
        new_mode = (octal != (mode_t)-1) ? octal : old_mode;

        if (octal == (mode_t)-1) {
            if (parse_symbolic(mode_str, &new_mode) != 0) {
                fprintf(stderr, "chmod: invalid mode: '%s'\n", mode_str);
                return 1;
            }
        }

        if (chmod(path, new_mode) != 0) {
            fprintf(stderr, "chmod: changing permissions of '%s': %s\n",
                    path, strerror(errno));
            return 1;
        }
    }

    if (flag_verbose || (flag_changes && old_mode != new_mode)) {
        if (old_mode != new_mode)
            printf("mode of '%s' changed from %04o to %04o\n",
                   path, old_mode, new_mode);
        else if (flag_verbose)
            printf("mode of '%s' retained as %04o\n", path, old_mode);
    }
    return 0;
}

static int chmod_tree(const char *path, const char *mode_str)
{
    int rc = do_chmod(path, mode_str);

    /* Open the path with O_NOFOLLOW so we never follow a trailing symlink.
     * We then use fstat + fdopendir on the same fd, eliminating the TOCTOU
     * window between the lstat "is it a directory?" check and opendir. */
    int dfd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (dfd < 0)
        return rc; /* not a dir, or no read perm — nothing to descend */

    struct stat st;
    if (fstat(dfd, &st) == 0 && S_ISDIR(st.st_mode)) {
        DIR *d = fdopendir(dfd);
        if (!d) {
            fprintf(stderr, "chmod: cannot open directory '%s': %s\n",
                    path, strerror(errno));
            close(dfd);
            return 1;
        }
        /* dfd is now owned by d; do not close it separately */
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            char child[4096];
            snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
            rc |= chmod_tree(child, mode_str);
        }
        closedir(d);
    } else {
        close(dfd);
    }

    return rc;
}

/* ---- main ---------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-R] [-v] [-c] MODE FILE...\n", prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "Rvc")) != -1) {
        switch (opt) {
        case 'R': flag_recursive = 1; break;
        case 'v': flag_verbose   = 1; break;
        case 'c': flag_changes   = 1; break;
        default:  usage(argv[0]);
        }
    }

    if (optind + 1 >= argc)
        usage(argv[0]);

    const char *mode_str = argv[optind++];

    int rc = 0;
    for (; optind < argc; optind++) {
        if (flag_recursive)
            rc |= chmod_tree(argv[optind], mode_str);
        else
            rc |= do_chmod(argv[optind], mode_str);
    }
    return rc;
}
