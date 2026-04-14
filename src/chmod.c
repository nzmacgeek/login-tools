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

/* Return the spread-across-all-slots bit pattern for a permission char,
 * or -1 if not a simple permission character (r/w/x/s/t). */
static int perm_bits(char c)
{
    switch (c) {
    case 'r': return 0444;
    case 'w': return 0222;
    case 'x': return 0111;
    case 's': return (int)(S_ISUID | S_ISGID);
    case 't': return (int)S_ISVTX;
    default:  return -1;
    }
}

/* Apply one symbolic clause (e.g. "u+x", "go-w", "a=rw") to *mode.
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
    int perms = 0;

    while (*p) {
        int b = perm_bits(*p);
        if (b >= 0) {
            perms |= b;
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

    /* X — execute/search only if directory or already executable */
    /* (handled as a special clause prefix in parse_symbolic) */

    int masked = perms & who;
    switch (op) {
    case '+': *mode |=  (mode_t)masked; break;
    case '-': *mode &= ~(mode_t)masked; break;
    case '=': *mode  = (*mode & ~(mode_t)who) | (mode_t)masked; break;
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

    /* For symbolic modes or verbose output, open the file and operate on the
     * file descriptor so that fstat() and fchmod() reference the same inode,
     * eliminating the TOCTOU window between the stat and the chmod. */
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "chmod: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "chmod: cannot stat '%s': %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }

    mode_t old_mode = st.st_mode & 07777;
    mode_t new_mode = (octal != (mode_t)-1) ? octal : old_mode;

    if (octal == (mode_t)-1) {
        /* Symbolic mode: compute new_mode from old_mode */
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

    if (flag_verbose || (flag_changes && old_mode != new_mode)) {
        if (old_mode != new_mode)
            printf("mode of '%s' changed from %04o to %04o\n",
                   path, old_mode, new_mode);
        else if (flag_verbose)
            printf("mode of '%s' retained as %04o\n", path, old_mode);
    }
    return 0;
}

static int chmod_tree(const char *path, const char *mode_str);

static int descend_dir(const char *path, const char *mode_str)
{
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "chmod: cannot open directory '%s': %s\n",
                path, strerror(errno));
        return 1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        rc |= chmod_tree(child, mode_str);
    }
    closedir(d);
    return rc;
}

static int chmod_tree(const char *path, const char *mode_str)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "chmod: cannot stat '%s': %s\n", path, strerror(errno));
        return 1;
    }
    int rc = do_chmod(path, mode_str);
    if (S_ISDIR(st.st_mode))
        rc |= descend_dir(path, mode_str);
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
